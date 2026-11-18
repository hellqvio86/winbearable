"""Non-destructive .wslconfig and /etc/wsl.conf management and 75% RAM sizing."""

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backends.registry import RegistryBackend, is_wsl2
from .backends.system import GIB_BYTES, SystemBackend
from .const import (
    DEFAULT_WSL_DISTRO,
    HIVE_HKLM,
    MIN_RECOMMENDED_WSL_VERSION,
    WSL_MIN_VERSION_BY_OPTION,
    WSL_POLICIES_KEY,
)
from .models import EnvironmentInfo, WslConfigSpec


class WslOperationError(RuntimeError):
    """Raised when a WSL configuration write or command fails."""


SECTION_HEADER_RE = re.compile(r"^\s*\[(?P<section>[^\]]+)\]\s*(?:#.*|;.*)?$")
KEY_VALUE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>[A-Za-z0-9_.-]+)(?P<sep>\s*=\s*)(?P<val>.*?)(?P<comment>\s*[#;].*)?$"
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

    for sec_key, (orig_sec, kv_map) in remaining_sections.items():
        if not kv_map:
            continue
        if output_lines and output_lines[-1].strip() != "":
            output_lines.append("")
        output_lines.append(f"[{orig_sec}]")
        for _, (orig_k, val) in kv_map.items():
            output_lines.append(f"{orig_k}={val}")
        consumed_by_section[sec_key].update(kv_map.keys())

    return "\n".join(output_lines).rstrip("\n") + "\n"


def _parse_version_tuple(version_str: str | None) -> tuple[int, ...] | None:
    if not version_str:
        return None
    nums = re.findall(r"\d+", version_str)
    if not nums:
        return None
    return tuple(int(n) for n in nums[:3])


def is_wsl_version_outdated(version_str: str | None) -> bool:
    """Return True when installed WSL version is below MIN_RECOMMENDED_WSL_VERSION."""
    parsed = _parse_version_tuple(version_str)
    min_parsed = _parse_version_tuple(MIN_RECOMMENDED_WSL_VERSION)
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
        wsl2_sec["kernelCommandLine"] = spec.kernel_command_line
    if spec.default_vhd_size is not None:
        wsl2_sec["defaultVhdSize"] = spec.default_vhd_size

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

    installed_ver = _parse_version_tuple(installed_wsl_version)
    if installed_ver is not None:
        for sec_dict in (wsl2_sec, experimental_sec):
            for key in list(sec_dict.keys()):
                min_req = _parse_version_tuple(WSL_MIN_VERSION_BY_OPTION.get(key))
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
            automount_sec["root"] = spec.automount_root
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
        if spec.default_user.strip().lower() == "root":
            raise WslOperationError("Refusing to set /etc/wsl.conf [user] default=root.")
        sections["user"] = {"default": spec.default_user.strip()}

    net_sec: dict[str, str] = {}
    if spec.hostname is not None:
        net_sec["hostname"] = spec.hostname
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


def _parse_ini_sections(text: str) -> dict[str, dict[str, str]]:
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


def _create_backup_file(target_path: Path, *, backup_dir: Path | None = None) -> Path | None:
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


def _atomic_write_text(target_path: Path, content: str, *, create_backup: bool = True) -> Path | None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path: Path | None = None
    existing_mode: int | None = None
    if target_path.is_file():
        existing_mode = stat.S_IMODE(target_path.stat().st_mode)
        if create_backup:
            backup_path = _create_backup_file(target_path)

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


@dataclass(frozen=True)
class WslDistroConfProbe:
    """Result of probing a WSL distro's /etc/wsl.conf before mutation."""

    status: str  # "exists" | "missing" | "error"
    content: str
    evidence: str


@dataclass(frozen=True)
class PreparedWslDistroPlan:
    """Prepared per-distro snapshot and desired /etc/wsl.conf content."""

    distro: str
    probe: WslDistroConfProbe
    merged_content: str
    changed: bool


@dataclass(frozen=True)
class PreparedWslPlan:
    """Prepared host .wslconfig and per-distro snapshots prior to any WSL mutation."""

    target_wslconfig: Path
    backup_path: Path | None
    host_memory_bytes: int
    host_memory_gib: str
    memory_limit_gib: int
    merged_wslconfig: str
    wslconfig_changed: bool
    warnings: tuple[str, ...]
    distro_plans: tuple[PreparedWslDistroPlan, ...]
    baseline_existed: bool = False
    baseline_sha256: str | None = None


def get_wsl_distro_guid(distro_name: str, registry: RegistryBackend | None = None) -> str | None:
    """Return the stable Lxss registration GUID for *distro_name* from HKCU, if present."""
    if registry is None:
        return None
    lxss_root = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
    try:
        subkeys = registry.list_subkeys("HKCU", lxss_root)
    except OSError:
        return None
    target_low = distro_name.strip().lower()
    for guid in subkeys:
        val = registry.get_value("HKCU", f"{lxss_root}\\{guid}", "DistributionName")
        if val is not None and str(val[0]).strip().lower() == target_low:
            return guid
    return None


_ENOENT_MARKERS = ("no such file", "cannot find", "does not exist")
_WSL_FAILURE_MARKERS = (
    "permission denied",
    "timed out",
    "timeout",
    "there is no distribution",
    "not installed",
    "wsl_e_",
    "access is denied",
    "failed",
    "error:",
)


def probe_distro_wsl_conf(distro: str, system: SystemBackend) -> WslDistroConfProbe:
    """Probe /etc/wsl.conf in *distro*, distinguishing confirmed absence from read/WSL errors."""
    try:
        test_res = system.run_wsl_command(
            ["-d", distro, "-u", "root", "--", "sh", "-c", "test -e /etc/wsl.conf; echo WB_RC=$?"]
        )
    except (WslOperationError, OSError, TimeoutError) as exc:
        return WslDistroConfProbe(status="error", content="", evidence=str(exc))

    test_stderr = (test_res.stderr or "").strip()
    if "WB_RC=1" in test_res.stdout and not test_stderr:
        return WslDistroConfProbe(status="missing", content="", evidence="confirmed_absent (WB_RC=1)")
    if "WB_RC=0" not in test_res.stdout:
        if test_res.returncode == 1 and not test_stderr and "WB_RC=" not in test_res.stdout:
            return WslDistroConfProbe(status="missing", content="", evidence="confirmed_absent (test -e returned 1)")
        if test_res.returncode != 0 or test_stderr:
            evidence = test_stderr or f"probe /etc/wsl.conf exited with code {test_res.returncode}"
            return WslDistroConfProbe(status="error", content="", evidence=evidence)

    try:
        cat_res = system.run_wsl_command(["-d", distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
    except (WslOperationError, OSError, TimeoutError) as exc:
        return WslDistroConfProbe(status="error", content="", evidence=str(exc))

    if cat_res.returncode == 0:
        return WslDistroConfProbe(status="exists", content=cat_res.stdout, evidence="read_ok")

    cat_stderr_low = (cat_res.stderr or "").strip().lower()
    if any(marker in cat_stderr_low for marker in _ENOENT_MARKERS):
        return WslDistroConfProbe(status="missing", content="", evidence=cat_res.stderr.strip())
    evidence = cat_res.stderr.strip() or f"cat /etc/wsl.conf exited with code {cat_res.returncode}"
    return WslDistroConfProbe(status="error", content="", evidence=evidence)


def prepare_wsl_plan(
    spec: WslConfigSpec,
    system: SystemBackend,
    *,
    wslconfig_path: Path | None = None,
    distros: tuple[str, ...] = (),
    create_host_backup: bool = True,
    backup_dir: Path | None = None,
) -> PreparedWslPlan:
    """Read host .wslconfig and probe all target distros before any WSL mutation occurs."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    baseline_existed = target_wslconfig.is_file()
    baseline_bytes = target_wslconfig.read_bytes() if baseline_existed else b""
    baseline_sha256 = hashlib.sha256(baseline_bytes).hexdigest() if baseline_existed else None
    existing_wslconfig = baseline_bytes.decode("utf-8").lstrip("\ufeff") if baseline_existed else ""

    host_memory_bytes = system.get_total_memory_bytes()
    host_memory_gib_str = format_host_memory_gib(host_memory_bytes)
    memory_gib = spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)

    warnings: list[str] = []
    desired_wslconfig_sections = build_wslconfig_sections(spec, host_memory_bytes, warnings=warnings)
    merged_wslconfig = merge_ini_preserving_comments(existing_wslconfig, desired_wslconfig_sections)
    wslconfig_changed = merged_wslconfig != existing_wslconfig

    backup_path: Path | None = None
    if create_host_backup and wslconfig_changed:
        backup_path = _create_backup_file(target_wslconfig, backup_dir=backup_dir)

    distro_sections = build_distro_wsl_conf_sections(spec)
    distro_plans: list[PreparedWslDistroPlan] = []
    for distro in distros:
        probe = probe_distro_wsl_conf(distro, system)
        if probe.status == "error":
            raise WslOperationError(f"Refusing to modify /etc/wsl.conf in '{distro}': {probe.evidence}")
        merged_distro_conf = merge_ini_preserving_comments(probe.content, distro_sections)
        distro_plans.append(
            PreparedWslDistroPlan(
                distro=distro,
                probe=probe,
                merged_content=merged_distro_conf,
                changed=merged_distro_conf != probe.content,
            )
        )

    return PreparedWslPlan(
        target_wslconfig=target_wslconfig,
        backup_path=backup_path,
        host_memory_bytes=host_memory_bytes,
        host_memory_gib=host_memory_gib_str,
        memory_limit_gib=memory_gib,
        merged_wslconfig=merged_wslconfig,
        wslconfig_changed=wslconfig_changed,
        warnings=tuple(warnings),
        distro_plans=tuple(distro_plans),
        baseline_existed=baseline_existed,
        baseline_sha256=baseline_sha256,
    )


def apply_wslconfig_target(plan: PreparedWslPlan) -> None:
    """Write and verify host .wslconfig using a pre-prepared plan."""
    if not plan.wslconfig_changed:
        return
    currently_exists = plan.target_wslconfig.is_file()
    if currently_exists != plan.baseline_existed:
        raise WslOperationError(
            f"Concurrent modification detected on {plan.target_wslconfig}: existence changed between plan and apply."
        )
    if plan.baseline_existed and plan.baseline_sha256 is not None:
        current_sha = hashlib.sha256(plan.target_wslconfig.read_bytes()).hexdigest()
        if current_sha != plan.baseline_sha256:
            raise WslOperationError(
                f"Concurrent modification detected on {plan.target_wslconfig}: content changed between plan and apply."
            )
    _atomic_write_text(plan.target_wslconfig, plan.merged_wslconfig, create_backup=plan.backup_path is None)
    verified_text = plan.target_wslconfig.read_text(encoding="utf-8")
    if verified_text != plan.merged_wslconfig:
        raise WslOperationError(f"Verification failed after writing {plan.target_wslconfig}.")


def lint_wsl_conf_lf(content: str) -> dict[str, Any]:
    """Lint wsl.conf text for CRLF (\\r\\n) or CR (\\r) line endings that break Linux/WSL parsers."""
    crlf_lines = [idx + 1 for idx, raw in enumerate(content.split("\n")) if "\r" in raw]
    return {
        "clean": not crlf_lines,
        "has_crlf": bool(crlf_lines),
        "crlf_lines": crlf_lines,
    }


def apply_distro_wsl_conf(distro_plan: PreparedWslDistroPlan, system: SystemBackend) -> None:
    """Write and byte-verify /etc/wsl.conf (LF-only) for a single prepared distro."""
    if not distro_plan.changed:
        return
    lf_content = distro_plan.merged_content.replace("\r\n", "\n").replace("\r", "\n")
    expected_sha256 = hashlib.sha256(lf_content.encode("utf-8")).hexdigest()
    write_res = system.run_wsl_command(
        ["-d", distro_plan.distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
        input_text=lf_content,
    )
    if write_res.returncode != 0:
        raise WslOperationError(f"Failed to write /etc/wsl.conf in '{distro_plan.distro}': {write_res.stderr}")

    sha_res = system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "sha256sum", "/etc/wsl.conf"])
    sha_tokens = sha_res.stdout.strip().split() if sha_res.returncode == 0 else []
    if sha_tokens and len(sha_tokens[0]) == 64 and sha_tokens[0].lower() != expected_sha256:
        raise WslOperationError(
            f"SHA-256 verification failed after writing /etc/wsl.conf in '{distro_plan.distro}' "
            f"(expected {expected_sha256}, got {sha_tokens[0].lower()})."
        )

    verify_res = system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
    if verify_res.returncode != 0 or "\r" in verify_res.stdout or verify_res.stdout != lf_content:
        raise WslOperationError(f"Verification failed after writing /etc/wsl.conf in '{distro_plan.distro}'.")


def plan_or_apply_wsl(
    spec: WslConfigSpec,
    system: SystemBackend,
    wslconfig_path: Path | None = None,
    distro: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Plan or apply .wslconfig (sizing memory to 75% of host RAM) and per-distro /etc/wsl.conf."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    existing_wslconfig = (
        target_wslconfig.read_text(encoding="utf-8").lstrip("\ufeff") if target_wslconfig.is_file() else ""
    )

    host_memory_bytes = system.get_total_memory_bytes()
    host_memory_gib_str = format_host_memory_gib(host_memory_bytes)
    memory_gib = spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)

    warnings: list[str] = []
    desired_wslconfig_sections = build_wslconfig_sections(spec, host_memory_bytes, warnings=warnings)
    merged_wslconfig = merge_ini_preserving_comments(existing_wslconfig, desired_wslconfig_sections)
    wslconfig_changed = merged_wslconfig != existing_wslconfig
    backup_path: Path | None = None

    distro_sections = build_distro_wsl_conf_sections(spec)
    distro_changed = False
    distro_existed = False
    distro_read_status = "skipped"
    distro_read_evidence = "no_distro"
    existing_distro_conf = ""
    merged_distro_conf = merge_ini_preserving_comments("", distro_sections)

    if distro is not None:
        probe = probe_distro_wsl_conf(distro, system)
        distro_read_status = probe.status
        distro_read_evidence = probe.evidence
        if probe.status == "error":
            if not dry_run:
                raise WslOperationError(f"Refusing to modify /etc/wsl.conf in '{distro}': {probe.evidence}")
            warnings.append(f"Could not read /etc/wsl.conf in '{distro}': {probe.evidence}")
        else:
            distro_existed = probe.status == "exists"
            existing_distro_conf = probe.content
            merged_distro_conf = merge_ini_preserving_comments(existing_distro_conf, distro_sections)
            distro_changed = merged_distro_conf != existing_distro_conf

    if not dry_run and wslconfig_changed:
        backup_path = _atomic_write_text(target_wslconfig, merged_wslconfig)
        verified_text = target_wslconfig.read_text(encoding="utf-8")
        if verified_text != merged_wslconfig:
            raise WslOperationError(f"Verification failed after writing {target_wslconfig}.")

    if not dry_run and distro is not None and distro_changed:
        try:
            apply_distro_wsl_conf(
                PreparedWslDistroPlan(
                    distro=distro,
                    probe=WslDistroConfProbe(distro_read_status, existing_distro_conf, distro_read_evidence),
                    merged_content=merged_distro_conf,
                    changed=True,
                ),
                system,
            )
        except Exception:
            if backup_path is not None and backup_path.is_file():
                shutil.copy2(backup_path, target_wslconfig)
            raise

    return {
        "dry_run": dry_run,
        "mode": spec.mode,
        "host_memory_bytes": host_memory_bytes,
        "host_memory_gib": host_memory_gib_str,
        "memory_limit_gib": memory_gib,
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_backup_path": str(backup_path) if backup_path is not None else None,
        "wslconfig_changed": wslconfig_changed,
        "distro_existed": distro_existed,
        "distro_read_status": distro_read_status,
        "distro_read_evidence": distro_read_evidence,
        "distro_previous_content": existing_distro_conf,
        "wslconfig_content": merged_wslconfig,
        "distro": distro,
        "distro_changed": distro_changed,
        "distro_restart_required": distro_changed,
        "distro_wsl_conf_content": merged_distro_conf,
        "warnings": warnings,
    }


def _parse_bool_flag(raw: str | None) -> bool | None:
    if raw is None or raw == "":
        return None
    low = raw.strip().lower()
    if low == "true":
        return True
    if low == "false":
        return False
    return None


def _read_proc_sys_value(proc_sys_root: Path, rel_path: str) -> str | None:
    target = proc_sys_root / rel_path
    try:
        if not target.is_file():
            return None
        return target.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_git_system_credential_helpers(git_config_path: Path | None = None) -> list[str]:
    if git_config_path is not None:
        if not git_config_path.is_file():
            return []
        sections = _parse_ini_sections(git_config_path.read_text(encoding="utf-8", errors="replace"))
        helper = sections.get("credential", {}).get("helper", "").strip()
        return [helper] if helper else []
    from .backends.system import NativeSystemBackend

    git_exe = NativeSystemBackend._resolve_git_exe()
    if git_exe is None:
        return []
    try:
        res = subprocess.run(
            [git_exe, "config", "--system", "--get-all", "credential.helper"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5.0,
            shell=False,
        )
        if res.returncode != 0:
            return []
        return [
            cleaned
            for line in res.stdout.splitlines()
            if (cleaned := line.replace("\x00", "").lstrip("\ufeff").strip())
        ]
    except OSError, subprocess.SubprocessError:
        return []


def _audit_credential_hygiene(
    git_helpers: list[str],
    ssh_dir: Path | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect git credential helpers, ~/.ssh permissions, and Windows SSH agent leakage."""
    issues: list[str] = []
    win_helpers = [h for h in git_helpers if _is_windows_credential_helper(h)]
    if win_helpers:
        issues.append(f"Windows git credential helper configured: {', '.join(win_helpers)}")

    target_env = env_vars if env_vars is not None else dict(os.environ)
    ssh_leak = False
    for var_name in ("SSH_AUTH_SOCK", "GIT_SSH", "GIT_SSH_COMMAND"):
        val = target_env.get(var_name, "")
        if val and ("/mnt/c/" in val.lower() or ".exe" in val.lower()):
            ssh_leak = True
            issues.append(f"{var_name} points to Windows host binary/socket: {val}")

    target_ssh = ssh_dir or (Path.home() / ".ssh")
    ssh_dir_mode: str | None = None
    insecure_keys: list[str] = []
    if target_ssh.is_dir():
        dir_mode = target_ssh.stat().st_mode & 0o777
        ssh_dir_mode = oct(dir_mode)
        if dir_mode & 0o077:
            issues.append(f"{target_ssh} permissions are {ssh_dir_mode} (expected 0o700)")
        for entry in sorted(target_ssh.iterdir()):
            if entry.is_symlink():
                try:
                    resolved = str(entry.resolve()).lower()
                except OSError:
                    resolved = ""
                if "/mnt/c/users" in resolved:
                    issues.append(f"SSH entry {entry} symlinks into Windows /mnt/c/Users ({resolved})")
            if not entry.is_file():
                continue
            name = entry.name
            if name.endswith(".pub") or name in {"known_hosts", "known_hosts.old", "config", "authorized_keys"}:
                continue
            key_mode = entry.stat().st_mode & 0o777
            if key_mode & 0o077:
                insecure_keys.append(f"{name} ({oct(key_mode)})")
                issues.append(f"Private key {entry} has overly permissive mode {oct(key_mode)} (expected 0o600)")

    return {
        "clean": len(issues) == 0,
        "issues": issues,
        "windows_git_helpers": win_helpers,
        "ssh_agent_windows_leak": ssh_leak,
        "ssh_dir_mode": ssh_dir_mode,
        "ssh_insecure_keys": insecure_keys,
    }


def audit_linux_side(
    wsl_conf_path: Path | None = None,
    sysctl_conf_path: Path | None = None,
    proc_sys_root: Path | None = None,
    systemd_marker_path: Path | None = None,
    git_config_path: Path | None = None,
    platform_override: str | None = None,
    ssh_dir: Path | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Audit Linux-side WSL2 settings: /etc/wsl.conf, sysctl baseline, systemd, and credential hygiene."""
    target_platform = platform_override or sys.platform
    is_linux = target_platform == "linux"
    if not is_linux:
        return {
            "is_linux": False,
            "is_wsl2": False,
            "distro": None,
            "wsl_conf_exists": False,
            "automount_enabled": None,
            "interop_enabled": None,
            "append_windows_path": None,
            "systemd_configured": None,
            "systemd_running": False,
            "sysctl_baseline_file_exists": False,
            "sysctl_baseline_applied": False,
            "sysctl_values": {},
            "git_system_credential_helper": [],
            "git_credential_helper_isolated": True,
            "credential_hygiene": {
                "clean": True,
                "issues": [],
                "windows_git_helpers": [],
                "ssh_agent_windows_leak": False,
                "ssh_dir_mode": None,
                "ssh_insecure_keys": [],
            },
        }

    wsl_conf = wsl_conf_path or Path("/etc/wsl.conf")
    has_wsl_conf = wsl_conf.is_file()
    conf_sections = _parse_ini_sections(wsl_conf.read_text(encoding="utf-8", errors="replace")) if has_wsl_conf else {}
    automount_sec = conf_sections.get("automount", {})
    interop_sec = conf_sections.get("interop", {})
    boot_sec = conf_sections.get("boot", {})

    sysctl_conf = sysctl_conf_path or Path("/etc/sysctl.d/99-winbearable-wsl.conf")
    proc_root = proc_sys_root or Path("/proc/sys")
    systemd_marker = systemd_marker_path or Path("/run/systemd/system")

    expected_sysctl = {
        "kernel.kptr_restrict": ("kernel/kptr_restrict", "2"),
        "kernel.dmesg_restrict": ("kernel/dmesg_restrict", "1"),
        "net.ipv4.conf.all.rp_filter": ("net/ipv4/conf/all/rp_filter", "1"),
        "net.ipv4.conf.default.rp_filter": ("net/ipv4/conf/default/rp_filter", "1"),
        "kernel.yama.ptrace_scope": ("kernel/yama/ptrace_scope", "1"),
        "fs.protected_hardlinks": ("fs/protected_hardlinks", "1"),
        "fs.protected_symlinks": ("fs/protected_symlinks", "1"),
        "vm.swappiness": ("vm/swappiness", "10"),
        "kernel.unprivileged_bpf_disabled": ("kernel/unprivileged_bpf_disabled", "1"),
    }
    sysctl_values = {key: _read_proc_sys_value(proc_root, rel_path) for key, (rel_path, _) in expected_sysctl.items()}
    sysctl_applied = all(sysctl_values.get(key) == expected for key, (_, expected) in expected_sysctl.items())

    git_helpers = _read_git_system_credential_helpers(git_config_path)
    credential_hygiene = _audit_credential_hygiene(git_helpers, ssh_dir=ssh_dir, env_vars=env_vars)
    git_isolated = len(credential_hygiene["windows_git_helpers"]) == 0

    return {
        "is_linux": True,
        "is_wsl2": is_wsl2()
        if platform_override is None
        else ("WSL_DISTRO_NAME" in os.environ or "WSL_INTEROP" in os.environ),
        "distro": os.environ.get("WSL_DISTRO_NAME"),
        "wsl_conf_path": str(wsl_conf),
        "wsl_conf_exists": has_wsl_conf,
        "automount_enabled": _parse_bool_flag(automount_sec.get("enabled")),
        "interop_enabled": _parse_bool_flag(interop_sec.get("enabled")),
        "append_windows_path": _parse_bool_flag(interop_sec.get("appendWindowsPath")),
        "systemd_configured": _parse_bool_flag(boot_sec.get("systemd")),
        "systemd_running": systemd_marker.is_dir(),
        "sysctl_baseline_file_exists": sysctl_conf.is_file(),
        "sysctl_baseline_applied": sysctl_applied,
        "sysctl_values": sysctl_values,
        "git_system_credential_helper": git_helpers,
        "git_credential_helper_isolated": git_isolated,
        "credential_hygiene": credential_hygiene,
    }


def detect_default_wsl_distro(
    system: SystemBackend | None,
    env: EnvironmentInfo,
) -> str | None:
    """Parse `wsl.exe --list --verbose` output to determine the active default distro (`*`)."""
    if system is None or not env.wsl_installed or not env.is_windows:
        return None
    try:
        res = system.run_wsl_command(["--list", "--verbose"])
    except OSError:
        return None
    if res.returncode != 0 or not res.stdout:
        return None
    for raw_line in res.stdout.splitlines():
        cleaned = raw_line.replace("\x00", "").lstrip("\ufeff").strip()
        if cleaned.startswith("*"):
            tokens = cleaned[1:].strip().split()
            if tokens:
                return tokens[0]
    return None


_DISTRO_EOL_VERSIONS: dict[str, set[str]] = {
    "ubuntu": {"18.04", "20.04", "22.10", "23.04", "23.10"},
    "debian": {"10", "11"},
    "fedora": {"38", "39", "40"},
}


def deep_audit_wsl_distro(system: SystemBackend, distro: str) -> dict[str, Any]:
    """Run read-only deep exposure checks inside a WSL2 distro via fixed-argv commands."""
    issues: list[str] = []
    uid_res = system.run_wsl_command(["-d", distro, "--", "id", "-u"])
    default_uid = uid_res.stdout.strip() if uid_res.returncode == 0 else None
    default_is_root = default_uid == "0"
    if default_is_root:
        issues.append(f"Distro '{distro}' default user is root (uid=0).")

    sudo_res = system.run_wsl_command(
        ["-d", distro, "-u", "root", "--", "grep", "-rn", "NOPASSWD", "/etc/sudoers", "/etc/sudoers.d"]
    )
    nopasswd_lines = (
        [ln.strip() for ln in sudo_res.stdout.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if sudo_res.returncode == 0
        else []
    )
    if nopasswd_lines:
        issues.append(f"Distro '{distro}' has NOPASSWD sudoers rules ({len(nopasswd_lines)}).")

    path_res = system.run_wsl_command(["-d", distro, "--", "printenv", "PATH"])
    win_in_path = "/mnt/c/" in path_res.stdout.lower() if path_res.returncode == 0 else False
    if win_in_path:
        issues.append(f"Distro '{distro}' includes Windows /mnt/c paths in $PATH.")

    os_rel = system.run_wsl_command(["-d", distro, "--", "cat", "/etc/os-release"])
    distro_id = ""
    version_id = ""
    if os_rel.returncode == 0:
        for ln in os_rel.stdout.splitlines():
            if ln.startswith("ID="):
                distro_id = ln.split("=", 1)[1].strip().strip('"').lower()
            elif ln.startswith("VERSION_ID="):
                version_id = ln.split("=", 1)[1].strip().strip('"')
    eol = version_id in _DISTRO_EOL_VERSIONS.get(distro_id, set())
    if eol:
        issues.append(f"Distro '{distro}' ({distro_id} {version_id}) is End-of-Life.")

    ss_res = system.run_wsl_command(["-d", distro, "--", "ss", "-ltnH"])
    listeners = [ln.strip() for ln in ss_res.stdout.splitlines() if ln.strip()] if ss_res.returncode == 0 else []

    sd_res = system.run_wsl_command(["-d", distro, "--", "test", "-d", "/run/systemd/system"])
    systemd_running = sd_res.returncode == 0

    wsl_conf_probe = probe_distro_wsl_conf(distro, system)
    wsl_conf_lint = lint_wsl_conf_lf(wsl_conf_probe.content) if wsl_conf_probe.status == "exists" else None
    if wsl_conf_lint is not None and wsl_conf_lint["has_crlf"]:
        issues.append(
            f"Distro '{distro}' /etc/wsl.conf contains CRLF (\\r\\n) line endings "
            f"(lines {wsl_conf_lint['crlf_lines']})."
        )

    return {
        "distro": distro,
        "default_uid": default_uid,
        "default_is_root": default_is_root,
        "nopasswd_sudoers_count": len(nopasswd_lines),
        "windows_paths_in_path": win_in_path,
        "os_id": distro_id,
        "version_id": version_id,
        "distro_eol": eol,
        "listening_sockets_count": len(listeners),
        "systemd_running": systemd_running,
        "wsl_conf_lint": wsl_conf_lint,
        "issues": issues,
    }


def audit_wsl(
    env: EnvironmentInfo,
    wslconfig_path: Path | None = None,
    system: SystemBackend | None = None,
    registry: RegistryBackend | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    """Audit host WSL2 status, distros, .wslconfig presence, policy blocks, and Linux-side configuration."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    has_wslconfig = target_wslconfig.is_file()
    wslconfig_text = target_wslconfig.read_text(encoding="utf-8") if has_wslconfig else ""
    sections = _parse_ini_sections(wslconfig_text) if has_wslconfig else {}
    wsl2_sec = sections.get("wsl2", {})

    default_wsl_distro = detect_default_wsl_distro(system, env)
    has_fedora = any(d.lower().startswith("fedora") for d in env.wsl_distros)
    has_ubuntu = any(d.lower().startswith("ubuntu") for d in env.wsl_distros)
    default_is_fedora = bool(default_wsl_distro and default_wsl_distro.lower().startswith("fedora"))
    fedora_warning = (
        "Modern Fedora WSL distros can break VS Code Remote-WSL; "
        f"Ubuntu ('{DEFAULT_WSL_DISTRO}') is recommended as the default WSL distro."
        if (default_is_fedora or (has_fedora and not has_ubuntu))
        else None
    )
    policy_info = detect_wsl_policies(registry) if registry is not None else {"blocked": False, "policies": {}}
    deep_results: list[dict[str, Any]] = []
    if deep and system is not None and env.is_windows and env.wsl_distros:
        for d in env.wsl_distros:
            deep_results.append(deep_audit_wsl_distro(system, d))

    return {
        "wsl_installed": env.wsl_installed,
        "wsl_version": env.wsl_version,
        "wsl_outdated": is_wsl_version_outdated(env.wsl_version),
        "wsl_policies": policy_info,
        "distros": list(env.wsl_distros),
        "default_wsl_distro": default_wsl_distro,
        "default_distro_is_fedora": default_is_fedora,
        "default_distro_recommendation": DEFAULT_WSL_DISTRO,
        "fedora_vscode_warning": fedora_warning,
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_exists": has_wslconfig,
        "mirrored_networking": wsl2_sec.get("networkingMode", "").lower() == "mirrored",
        "firewall_enabled": wsl2_sec.get("firewall", "").lower() == "true",
        "dns_tunneling": wsl2_sec.get("dnsTunneling", "").lower() == "true",
        "linux": audit_linux_side(),
        "deep": {"distros": deep_results, "issues": [iss for dr in deep_results for iss in dr["issues"]]}
        if deep
        else None,
    }


WSL_LINUX_SYSCTL_CONF = """# Managed by winbearable (wb wsl baseline)
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.yama.ptrace_scope = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
vm.swappiness = 10
kernel.unprivileged_bpf_disabled = 1
"""


def install_wsl_distro(
    system: SystemBackend,
    distro: str = DEFAULT_WSL_DISTRO,
    web_download: bool = False,
    dry_run: bool = True,
    set_default: bool = True,
) -> dict[str, Any]:
    """Install a WSL2 distribution via wsl.exe --install and optionally set it as default."""
    cmd = ["--install", "-d", distro]
    if web_download:
        cmd.append("--web-download")
    returncode = 0
    default_returncode: int | None = None
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
        if returncode == 0 and set_default:
            def_res = system.run_wsl_command(["--set-default", distro])
            default_returncode = def_res.returncode
            if default_returncode != 0:
                returncode = default_returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "web_download": web_download,
        "set_default": set_default,
        "default_returncode": default_returncode,
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def set_default_wsl_distro(
    system: SystemBackend,
    distro: str = DEFAULT_WSL_DISTRO,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Set the default Windows WSL2 distribution via `wsl.exe --set-default`."""
    cmd = ["--set-default", distro]
    returncode = 0
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def export_wsl_distro(
    system: SystemBackend,
    distro: str,
    output_file: Path,
    dry_run: bool = True,
    keep_last: int | None = None,
) -> dict[str, Any]:
    """Export a WSL2 distribution to a backup tarball via wsl.exe --export and record sha256."""
    import hashlib

    cmd = ["--export", distro, str(output_file)]
    returncode = 0
    sha256_hex: str | None = None
    pruned_files: list[str] = []
    if not dry_run:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
        if returncode == 0 and output_file.is_file():
            sha256_hex = hashlib.sha256(output_file.read_bytes()).hexdigest()
            output_file.with_suffix(f"{output_file.suffix}.sha256").write_text(
                f"{sha256_hex}  {output_file.name}\n",
                encoding="utf-8",
            )
            if keep_last is not None and keep_last > 0:
                other_tarballs = sorted(
                    (
                        p
                        for p in output_file.parent.glob(f"{distro}-*.tar")
                        if p.is_file() and p.resolve() != output_file.resolve()
                    ),
                    key=lambda p: (p.stat().st_mtime, p.name),
                    reverse=True,
                )
                for stale in other_tarballs[max(0, keep_last - 1) :]:
                    stale.unlink(missing_ok=True)
                    pruned_files.append(str(stale))
                    stale_sha = stale.with_suffix(f"{stale.suffix}.sha256")
                    if stale_sha.is_file():
                        stale_sha.unlink(missing_ok=True)
                        pruned_files.append(str(stale_sha))
    return {
        "dry_run": dry_run,
        "distro": distro,
        "output_file": str(output_file),
        "sha256": sha256_hex,
        "pruned_files": pruned_files,
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def update_wsl(system: SystemBackend, dry_run: bool = True) -> dict[str, Any]:
    """Run `wsl.exe --update` and `wsl.exe --set-default-version 2` (dry-run by default)."""
    cmds = [["--update"], ["--set-default-version", "2"]]
    returncode = 0
    if not dry_run:
        for c in cmds:
            res = system.run_wsl_command(c)
            if res.returncode != 0:
                returncode = res.returncode
                break
    return {
        "dry_run": dry_run,
        "commands": [["wsl.exe", *c] for c in cmds],
        "returncode": returncode,
    }


def set_wsl_distro_sparse(
    system: SystemBackend,
    distro: str,
    sparse: bool = True,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Configure sparse VHD mode for a WSL2 distro via `wsl.exe --manage <distro> --set-sparse`."""
    cmd = ["--manage", distro, "--set-sparse", "true" if sparse else "false"]
    returncode = 0
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "sparse": sparse,
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def import_wsl_distro(
    system: SystemBackend,
    distro: str,
    install_dir: Path,
    tarball_file: Path,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Import a WSL2 distribution from a rootfs tarball via wsl.exe --import."""
    cmd = ["--import", distro, str(install_dir), str(tarball_file), "--version", "2"]
    returncode = 0
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "install_dir": str(install_dir),
        "tarball_file": str(tarball_file),
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def _is_windows_credential_helper(helper: str) -> bool:
    low = helper.strip().lower()
    return any(token in low for token in ("wincred", "gcm", ".exe", "/mnt/c/"))


def detect_wsl_package_manager(system: SystemBackend, distro: str) -> str:
    """Detect the primary Linux package manager inside a WSL distro."""
    probe = (
        "if command -v apt-get >/dev/null; then echo apt; "
        "elif command -v dnf >/dev/null; then echo dnf; "
        "elif command -v pacman >/dev/null; then echo pacman; "
        "else echo unsupported; fi"
    )
    res = system.run_wsl_command(["-d", distro, "-u", "root", "--", "sh", "-c", probe])
    if res.returncode != 0:
        return "unsupported"
    out = res.stdout.strip().splitlines()[-1].strip().lower() if res.stdout.strip() else ""
    return out if out in {"apt", "dnf", "pacman"} else "unsupported"


def apply_wsl_linux_baseline(
    system: SystemBackend,
    distro: str = DEFAULT_WSL_DISTRO,
    dotfiles_repo: str | None = None,
    dev_packages: bool = False,
    auto_patch: bool = True,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Configure sysctl baseline, isolate Windows git credential helper, auto-patch, and optional packages/dotfiles."""
    sysctl_path = "/etc/sysctl.d/99-winbearable-wsl.conf"
    steps: list[str] = [
        (
            f"Write {sysctl_path} (kptr_restrict=2, dmesg_restrict=1, rp_filter=1, "
            "ptrace_scope=1, protected links, swappiness=10, bpf_disabled=1)"
        ),
        "Reload sysctl settings via sysctl --system",
        "Remove Windows git credential helpers from system config (preserving native Linux helpers)",
    ]
    if auto_patch:
        steps.append("Enable automatic security updates (unattended-upgrades; opt-out via --no-auto-patch)")
    if dev_packages:
        steps.append("Install minimal dev packages (git, curl, jq, build-essential/base-devel)")
    if dotfiles_repo:
        steps.append(f"Apply dotfiles via chezmoi init --apply {dotfiles_repo}")

    warnings: list[str] = []
    package_manager: str | None = None

    if not dry_run:
        r1 = system.run_wsl_command(
            ["-d", distro, "-u", "root", "--", "tee", sysctl_path],
            input_text=WSL_LINUX_SYSCTL_CONF,
        )
        if r1.returncode != 0:
            raise WslOperationError(f"Failed to write {sysctl_path} in '{distro}': {r1.stderr}")
        r2 = system.run_wsl_command(["-d", distro, "-u", "root", "--", "sysctl", "--system"])
        if r2.returncode != 0:
            raise WslOperationError(f"Failed to reload sysctl in '{distro}': {r2.stderr}")
        r3_get = system.run_wsl_command(
            ["-d", distro, "-u", "root", "--", "git", "config", "--system", "--get-all", "credential.helper"]
        )
        if r3_get.returncode == 0:
            for helper in [line.strip() for line in r3_get.stdout.splitlines() if line.strip()]:
                if _is_windows_credential_helper(helper):
                    r3_unset = system.run_wsl_command(
                        [
                            "-d",
                            distro,
                            "-u",
                            "root",
                            "--",
                            "git",
                            "config",
                            "--system",
                            "--unset",
                            "credential.helper",
                            helper,
                        ]
                    )
                    if r3_unset.returncode not in (0, 5):
                        raise WslOperationError(
                            f"Failed to remove Windows git credential.helper '{helper}' in '{distro}': "
                            f"{r3_unset.stderr}"
                        )
        elif r3_get.returncode not in (1, 5):
            raise WslOperationError(f"Failed to inspect git credential.helper in '{distro}': {r3_get.stderr}")
        if auto_patch or dev_packages:
            package_manager = detect_wsl_package_manager(system, distro)
        if auto_patch:
            if package_manager == "apt":
                patch_cmd = (
                    "DEBIAN_FRONTEND=noninteractive apt-get update && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades && "
                    'printf \'APT::Periodic::Update-Package-Lists "1";\\n'
                    'APT::Periodic::Unattended-Upgrade "1";\\n\' '
                    "> /etc/apt/apt.conf.d/20auto-upgrades"
                )
            elif package_manager == "dnf":
                patch_cmd = "dnf install -y dnf-automatic && systemctl enable --now dnf-automatic.timer || true"
            else:
                patch_cmd = ""
                warnings.append(
                    f"Unsupported package manager '{package_manager}' in '{distro}'; "
                    "skipped automatic security updates."
                )
            if patch_cmd:
                r_patch = system.run_wsl_command(["-d", distro, "-u", "root", "--", "sh", "-c", patch_cmd])
                if r_patch.returncode != 0:
                    raise WslOperationError(f"Failed to enable auto-patching in '{distro}': {r_patch.stderr}")
        if dev_packages:
            if package_manager == "apt":
                pkg_cmd = (
                    "DEBIAN_FRONTEND=noninteractive apt-get update && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y git curl jq build-essential"
                )
            elif package_manager == "dnf":
                pkg_cmd = "dnf install -y git curl jq gcc gcc-c++ make"
            elif package_manager == "pacman":
                pkg_cmd = "pacman -Sy --noconfirm git curl jq base-devel"
            else:
                raise WslOperationError(
                    f"Unsupported package manager '{package_manager}' in '{distro}' for --dev-packages "
                    "(requires apt-get, dnf, or pacman)."
                )
            r_pkg = system.run_wsl_command(["-d", distro, "-u", "root", "--", "sh", "-c", pkg_cmd])
            if r_pkg.returncode != 0:
                raise WslOperationError(f"Failed to install dev packages in '{distro}': {r_pkg.stderr}")
        if dotfiles_repo:
            r4 = system.run_wsl_command(["-d", distro, "--", "chezmoi", "init", "--apply", dotfiles_repo])
            if r4.returncode != 0:
                raise WslOperationError(f"Failed to apply chezmoi dotfiles in '{distro}': {r4.stderr}")

    return {
        "dry_run": dry_run,
        "distro": distro,
        "sysctl_path": sysctl_path,
        "sysctl_content": WSL_LINUX_SYSCTL_CONF,
        "auto_patch": auto_patch,
        "dev_packages": dev_packages,
        "dotfiles_repo": dotfiles_repo,
        "package_manager": package_manager,
        "warnings": warnings,
        "steps": steps,
    }
