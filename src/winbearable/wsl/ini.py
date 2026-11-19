"""INI comment-preserving parser/merger, memory sizing, and .wslconfig / wsl.conf builders."""

from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import GIB_BYTES
from ..const import (
    HIVE_HKLM,
    WSL_POLICIES_KEY,
)
from ..models import WslConfigSpec
from .consts import MIN_RECOMMENDED_WSL_VERSION, WSL_MIN_VERSION_BY_OPTION


class WslOperationError(RuntimeError):
    """Raised when a WSL configuration write or command fails."""


WSL_DISTRO_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DOTFILES_REPO_RE = re.compile(
    r"^(?:https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]+|git@[A-Za-z0-9._-]+:[A-Za-z0-9._/-]+(?:\.git)?|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$"
)


def validate_wsl_distro_name(distro: str) -> str:
    """Validate that a WSL distro name is safe to pass to wsl.exe."""
    if not isinstance(distro, str) or ".." in distro or not WSL_DISTRO_NAME_RE.fullmatch(distro):
        raise WslOperationError(
            f"Invalid WSL distro name {distro!r}: must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$ without '..'."
        )
    return distro


def validate_dotfiles_repo(repo: str) -> str:
    """Validate a dotfiles repo URL or owner/repo slug for chezmoi init."""
    if (
        not isinstance(repo, str)
        or repo.startswith("-")
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in repo)
        or any(ch in repo for ch in (" ", "\t", '"', "'", "`", "$", ";", "|", "&", "<", ">"))
        or ".." in repo
        or not DOTFILES_REPO_RE.fullmatch(repo)
    ):
        raise WslOperationError(f"Invalid chezmoi dotfiles_repo {repo!r}.")
    return repo


SECTION_HEADER_RE = re.compile(r"^\s*\[(?P<section>[^\]]+)\]\s*(?:#.*|;.*)?$")


KEY_VALUE_RE = re.compile(
    r'^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*=\s*)(?P<val>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^#;\r\n]*?)(?P<comment>\s*[#;].*)?$'
)


def calculate_wsl_memory_gib(host_memory_bytes: int) -> int:
    """Set WSL 2 memory limit to 75% of the Windows host's physical RAM, rounded up to whole GiB.

    Ported directly from linux-scripts/wsl/configure_memory.sh:
        memory_gib = (host_memory_bytes * 3 + 4 * gib - 1) // (4 * gib)
    """
    if host_memory_bytes <= 0:
        raise ValueError("Detected host RAM must be greater than zero.")
    return (host_memory_bytes * 3 + 4 * GIB_BYTES - 1) // (4 * GIB_BYTES)


def format_host_memory_gib(host_memory_bytes: int) -> str:
    """Format host physical RAM in tenths of a GiB (matching linux-scripts/wsl/configure_memory.sh)."""
    if host_memory_bytes <= 0:
        raise ValueError("Detected host RAM must be greater than zero.")
    tenths_gib = (host_memory_bytes * 10 + GIB_BYTES // 2) // GIB_BYTES
    return f"{tenths_gib // 10}.{tenths_gib % 10}"


def merge_ini_preserving_comments(
    existing_text: str,
    desired_sections: dict[str, dict[str, str]],
    *,
    case_insensitive: bool = True,
) -> str:
    """Merge desired INI sections/keys into existing_text while preserving comments and custom keys."""
    for sec, kv_map in desired_sections.items():
        if any(ch in sec for ch in ("\r", "\n", "\x00", "]")):
            raise ValueError(f"Invalid characters in INI section name: {sec!r}")
        for k, v in kv_map.items():
            if any(ch in k for ch in ("\r", "\n", "\x00", "=")):
                raise ValueError(f"Invalid characters in INI key: {k!r}")
            if any(ch in v for ch in ("\r", "\n", "\x00")):
                raise ValueError(f"Invalid characters in INI value for {k!r}")

    def _norm(name: str) -> str:
        return name.lower() if case_insensitive else name

    cleaned_text = existing_text.lstrip("\ufeff")
    lines = cleaned_text.splitlines() if cleaned_text else []

    remaining_sections: dict[str, tuple[str, dict[str, tuple[str, str]]]] = {
        _norm(sec): (sec, {_norm(k): (k, v) for k, v in kv_map.items()}) for sec, kv_map in desired_sections.items()
    }
    consumed_by_section: dict[str, set[str]] = {sec_key: set() for sec_key in remaining_sections}

    output_lines: list[str] = []
    current_section_key: str | None = None

    def flush_remaining_keys_for_section(sec_key: str | None) -> None:
        if sec_key is None or sec_key not in remaining_sections:
            return
        _, pending = remaining_sections[sec_key]
        for norm_k, (orig_k, val) in list(pending.items()):
            output_lines.append(f"{orig_k}={val}")
            consumed_by_section[sec_key].add(norm_k)
            del pending[norm_k]

    for raw_line in lines:
        line = raw_line.rstrip("\r")
        sec_match = SECTION_HEADER_RE.match(line)
        if sec_match is not None:
            flush_remaining_keys_for_section(current_section_key)
            current_section_key = _norm(sec_match.group("section").strip())
            output_lines.append(line)
            continue

        kv_match = KEY_VALUE_RE.match(line)
        if kv_match is not None and current_section_key in remaining_sections:
            key_name = kv_match.group("key")
            norm_key = _norm(key_name)
            _, sec_pending = remaining_sections[current_section_key]
            if norm_key in sec_pending:
                indent = kv_match.group("indent")
                comment = kv_match.group("comment") or ""
                _, new_val = sec_pending.pop(norm_key)
                consumed_by_section[current_section_key].add(norm_key)
                output_lines.append(f"{indent}{key_name}={new_val}{comment}")
                continue
            if norm_key in consumed_by_section[current_section_key]:
                # Drop duplicate conflicting key in the same section
                continue

        output_lines.append(line)

    flush_remaining_keys_for_section(current_section_key)

    for sec_key, (orig_sec, sec_kv_map) in remaining_sections.items():
        if not sec_kv_map:
            continue
        if output_lines and output_lines[-1].strip() != "":
            output_lines.append("")
        output_lines.append(f"[{orig_sec}]")
        for _, (orig_k, val) in sec_kv_map.items():
            output_lines.append(f"{orig_k}={val}")
        consumed_by_section[sec_key].update(sec_kv_map.keys())

    return "\n".join(output_lines).rstrip("\n") + "\n"


def parse_version_tuple(version_str: str | None) -> tuple[int, ...] | None:
    if not version_str:
        return None
    nums = re.findall(r"\d+", version_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums[:3])


def is_wsl_version_outdated(version_str: str | None) -> bool:
    """Return True when installed WSL version is below MIN_RECOMMENDED_WSL_VERSION."""
    parsed = parse_version_tuple(version_str)
    min_parsed = parse_version_tuple(MIN_RECOMMENDED_WSL_VERSION)
    if parsed is None or min_parsed is None:
        return False
    return parsed < min_parsed


def detect_wsl_policies(registry: RegistryBackend) -> dict[str, Any]:
    """Read host-side WSL policies under HKLM\\SOFTWARE\\Policies\\Microsoft\\WSL."""
    policy_names = (
        "AllowWSL",
        "AllowWSL1",
        "AllowCustomKernel",
        "AllowCustomKernelUserSetting",
        "DefaultNetworkingMode",
    )
    policies: dict[str, Any] = {}
    blocked = False
    for name in policy_names:
        try:
            val = registry.get_value(HIVE_HKLM, WSL_POLICIES_KEY, name)
        except PermissionError:
            val = None
        if val is not None:
            policies[name] = val[0]
            if name == "AllowWSL" and val[0] == 0:
                blocked = True
    return {"blocked": blocked, "policies": policies}


def _sanitize_ini_value(val: str, field_name: str) -> str:
    """Reject CR/LF in INI values to prevent key/section injection."""
    if "\r" in val or "\n" in val:
        raise WslOperationError(f"Invalid newline in WSL configuration value for '{field_name}'.")
    return val


def build_wslconfig_sections(
    spec: WslConfigSpec,
    host_memory_bytes: int,
    installed_wsl_version: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, dict[str, str]]:
    """Build desired [wsl2] and [experimental] sections for %UserProfile%\\.wslconfig (75% host RAM)."""
    sized_memory_gb = spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)
    swap_gb = max(2, sized_memory_gb // 4)

    wsl2_sec: dict[str, str] = {
        "networkingMode": spec.networking_mode,
        "dnsTunneling": str(spec.dns_tunneling).lower(),
        "firewall": str(spec.firewall).lower(),
        "autoProxy": str(spec.auto_proxy).lower(),
        "memory": f"{sized_memory_gb}GB",
        "swap": f"{swap_gb}GB",
    }
    if spec.processors is not None:
        wsl2_sec["processors"] = str(spec.processors)
    if spec.vm_idle_timeout is not None:
        wsl2_sec["vmIdleTimeout"] = str(spec.vm_idle_timeout)

    if spec.mode == "strict":
        wsl2_sec["guiApplications"] = "false" if spec.gui_applications is None else str(spec.gui_applications).lower()
        wsl2_sec["nestedVirtualization"] = (
            "false" if spec.nested_virtualization is None else str(spec.nested_virtualization).lower()
        )
        wsl2_sec["debugConsole"] = "false" if spec.debug_console is None else str(spec.debug_console).lower()
    else:
        if spec.gui_applications is not None:
            wsl2_sec["guiApplications"] = str(spec.gui_applications).lower()
        if spec.nested_virtualization is not None:
            wsl2_sec["nestedVirtualization"] = str(spec.nested_virtualization).lower()
        if spec.debug_console is not None:
            wsl2_sec["debugConsole"] = str(spec.debug_console).lower()

    if spec.kernel_command_line is not None:
        wsl2_sec["kernelCommandLine"] = _sanitize_ini_value(spec.kernel_command_line, "kernel_command_line")
    if spec.default_vhd_size is not None:
        vhd_val = _sanitize_ini_value(spec.default_vhd_size.strip(), "default_vhd_size")
        if not re.fullmatch(r"\d+(?:[KMGTP]?B)?", vhd_val, re.IGNORECASE):
            raise WslOperationError(f"Invalid default_vhd_size {spec.default_vhd_size!r}.")
        wsl2_sec["defaultVhdSize"] = vhd_val

    experimental_sec: dict[str, str] = {
        "autoMemoryReclaim": "gradual",
        "sparseVhd": "true",
    }
    if spec.host_address_loopback is not None:
        experimental_sec["hostAddressLoopback"] = str(spec.host_address_loopback).lower()
    if spec.ignored_ports is not None:
        experimental_sec["ignoredPorts"] = ",".join(str(p) for p in spec.ignored_ports)
    if spec.best_effort_dns_parsing is not None:
        experimental_sec["bestEffortDnsParsing"] = str(spec.best_effort_dns_parsing).lower()

    installed_ver = parse_version_tuple(installed_wsl_version)
    if installed_ver is not None:
        for sec_dict in (wsl2_sec, experimental_sec):
            for key in list(sec_dict.keys()):
                min_req = parse_version_tuple(WSL_MIN_VERSION_BY_OPTION.get(key))
                if min_req is not None and installed_ver < min_req:
                    sec_dict.pop(key)
                    if warnings is not None:
                        warnings.append(
                            f"Skipped .wslconfig key '{key}' (requires WSL >= {WSL_MIN_VERSION_BY_OPTION[key]}, "
                            f"installed {installed_wsl_version})."
                        )

    return {
        "wsl2": wsl2_sec,
        "experimental": experimental_sec,
    }


def build_distro_wsl_conf_sections(spec: WslConfigSpec) -> dict[str, dict[str, str]]:
    """Build desired /etc/wsl.conf sections for either 'strict' or 'convenient' mode."""
    boot_sec = {"systemd": str(spec.systemd).lower()}
    if spec.mode == "strict":
        sections: dict[str, dict[str, str]] = {
            "boot": boot_sec,
            "automount": {
                "enabled": "false",
            },
            "interop": {
                "enabled": "false",
                "appendWindowsPath": "false",
            },
        }
    else:
        automount_sec: dict[str, str] = {
            "enabled": "true",
            "options": '"metadata,umask=22,fmask=11"',
        }
        if spec.automount_root is not None:
            root_val = _sanitize_ini_value(spec.automount_root.strip(), "automount_root")
            if not re.fullmatch(r"/[A-Za-z0-9._/-]*", root_val) or "#" in root_val or ";" in root_val:
                raise WslOperationError(f"Invalid automount_root {spec.automount_root!r}.")
            automount_sec["root"] = root_val
        if spec.cross_distro is not None:
            automount_sec["crossDistro"] = str(spec.cross_distro).lower()
        sections = {
            "boot": boot_sec,
            "automount": automount_sec,
            "interop": {
                "enabled": "true",
                "appendWindowsPath": "false",
            },
        }

    if spec.default_user is not None:
        user_val = _sanitize_ini_value(spec.default_user.strip(), "default_user")
        if user_val.lower() == "root" or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}\$?", user_val):
            raise WslOperationError(f"Invalid or forbidden /etc/wsl.conf [user] default={spec.default_user!r}.")
        sections["user"] = {"default": user_val}

    net_sec: dict[str, str] = {}
    if spec.hostname is not None:
        host_val = _sanitize_ini_value(spec.hostname.strip(), "hostname")
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", host_val):
            raise WslOperationError(f"Invalid WSL hostname {spec.hostname!r}.")
        net_sec["hostname"] = host_val
    if spec.generate_hosts is not None:
        net_sec["generateHosts"] = str(spec.generate_hosts).lower()
    if spec.generate_resolv_conf is not None:
        net_sec["generateResolvConf"] = str(spec.generate_resolv_conf).lower()
    if net_sec:
        sections["network"] = net_sec

    return sections


def get_default_wslconfig_path() -> Path:
    """Return %UserProfile%\\.wslconfig path."""
    return Path.home() / ".wslconfig"


def parse_ini_sections(text: str) -> dict[str, dict[str, str]]:
    """Parse INI text structurally, ignoring comments and whitespace."""
    sections: dict[str, dict[str, str]] = {}
    current_section: str | None = None
    for raw_line in text.lstrip("\ufeff").splitlines():
        line = raw_line.rstrip("\r").strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        sec_match = SECTION_HEADER_RE.match(line)
        if sec_match is not None:
            current_section = sec_match.group("section").strip()
            sections.setdefault(current_section, {})
            continue
        kv_match = KEY_VALUE_RE.match(line)
        if kv_match is not None and current_section is not None:
            key_name = kv_match.group("key").strip()
            val = kv_match.group("val").strip()
            sections[current_section][key_name] = val
    return sections


def create_backup_file(target_path: Path, *, backup_dir: Path | None = None) -> Path | None:
    """Create a durable .bak copy of *target_path* in *backup_dir* (or sibling) if it exists."""
    if not target_path.is_file():
        return None
    if backup_dir is not None:
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / f"{target_path.name}.bak"
    else:
        backup_path = target_path.with_suffix(f"{target_path.suffix}.bak")
    shutil.copy2(target_path, backup_path)
    return backup_path


def atomic_write_text(target_path: Path, content: str, *, create_backup: bool = True) -> Path | None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path: Path | None = None
    existing_mode: int | None = None
    if target_path.is_file():
        existing_mode = stat.S_IMODE(target_path.stat().st_mode)
        if create_backup:
            backup_path = create_backup_file(target_path)

    fd, temp_path_str = tempfile.mkstemp(
        prefix=f"{target_path.name}.",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if existing_mode is not None:
            os.chmod(temp_path_str, existing_mode)
        os.replace(temp_path_str, target_path)
    except Exception:
        if os.path.exists(temp_path_str):
            os.unlink(temp_path_str)
        raise
    return backup_path
