"""Non-destructive .wslconfig and /etc/wsl.conf management and 75% RAM sizing."""

import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .backends.system import GIB_BYTES, SystemBackend
from .models import EnvironmentInfo, WslConfigSpec

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


def merge_ini_preserving_comments(existing_text: str, desired_sections: dict[str, dict[str, str]]) -> str:
    """Merge desired INI sections/keys into existing_text while preserving comments and custom keys."""
    lines = existing_text.splitlines() if existing_text else []
    remaining_sections: dict[str, dict[str, str]] = {
        sec: dict(kv_map) for sec, kv_map in desired_sections.items()
    }

    output_lines: list[str] = []
    current_section: str | None = None

    def flush_remaining_keys_for_section(sec_name: str | None) -> None:
        if sec_name is None or sec_name not in remaining_sections:
            return
        pending = remaining_sections[sec_name]
        for key, val in list(pending.items()):
            output_lines.append(f"{key}={val}")
            del pending[key]

    for raw_line in lines:
        line = raw_line.rstrip("\r")
        sec_match = SECTION_HEADER_RE.match(line)
        if sec_match is not None:
            flush_remaining_keys_for_section(current_section)
            current_section = sec_match.group("section").strip()
            output_lines.append(line)
            continue

        kv_match = KEY_VALUE_RE.match(line)
        if kv_match is not None and current_section in remaining_sections:
            key_name = kv_match.group("key")
            sec_pending = remaining_sections[current_section]
            if key_name in sec_pending:
                indent = kv_match.group("indent")
                comment = kv_match.group("comment") or ""
                new_val = sec_pending.pop(key_name)
                output_lines.append(f"{indent}{key_name}={new_val}{comment}")
                continue

        output_lines.append(line)

    flush_remaining_keys_for_section(current_section)

    for sec_name, kv_map in remaining_sections.items():
        if not kv_map:
            continue
        if output_lines and output_lines[-1].strip() != "":
            output_lines.append("")
        output_lines.append(f"[{sec_name}]")
        for key, val in kv_map.items():
            output_lines.append(f"{key}={val}")

    return "\n".join(output_lines).rstrip("\n") + "\n"


def build_wslconfig_sections(spec: WslConfigSpec, host_memory_bytes: int) -> dict[str, dict[str, str]]:
    """Build desired [wsl2] and [experimental] sections for %UserProfile%\\.wslconfig (75% host RAM)."""
    sized_memory_gb = (
        spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)
    )
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

    experimental_sec: dict[str, str] = {
        "autoMemoryReclaim": "gradual",
        "sparseVhd": "true",
    }
    return {
        "wsl2": wsl2_sec,
        "experimental": experimental_sec,
    }


def build_distro_wsl_conf_sections(spec: WslConfigSpec) -> dict[str, dict[str, str]]:
    """Build desired /etc/wsl.conf sections for either 'strict' or 'convenient' mode."""
    boot_sec = {"systemd": str(spec.systemd).lower()}
    if spec.mode == "strict":
        return {
            "boot": boot_sec,
            "automount": {
                "enabled": "false",
            },
            "interop": {
                "enabled": "false",
                "appendWindowsPath": "false",
            },
        }
    return {
        "boot": boot_sec,
        "automount": {
            "enabled": "true",
            "options": '"metadata,umask=22,fmask=11"',
        },
        "interop": {
            "enabled": "true",
            "appendWindowsPath": "false",
        },
    }


def get_default_wslconfig_path() -> Path:
    """Return %UserProfile%\\.wslconfig path."""
    return Path.home() / ".wslconfig"


def _atomic_write_text(target_path: Path, content: str) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path_str = tempfile.mkstemp(
        prefix=f"{target_path.name}.",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_path_str, target_path)
    except Exception:
        if os.path.exists(temp_path_str):
            os.unlink(temp_path_str)
        raise


def plan_or_apply_wsl(
    spec: WslConfigSpec,
    system: SystemBackend,
    wslconfig_path: Path | None = None,
    distro: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Plan or apply .wslconfig (sizing memory to 75% of host RAM) and per-distro /etc/wsl.conf."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    existing_wslconfig = target_wslconfig.read_text(encoding="utf-8") if target_wslconfig.is_file() else ""

    host_memory_bytes = system.get_total_memory_bytes()
    host_memory_gib_str = format_host_memory_gib(host_memory_bytes)
    memory_gib = spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)

    desired_wslconfig_sections = build_wslconfig_sections(spec, host_memory_bytes)
    merged_wslconfig = merge_ini_preserving_comments(existing_wslconfig, desired_wslconfig_sections)
    wslconfig_changed = merged_wslconfig != existing_wslconfig

    if not dry_run and wslconfig_changed:
        _atomic_write_text(target_wslconfig, merged_wslconfig)

    distro_sections = build_distro_wsl_conf_sections(spec)
    distro_changed = False
    merged_distro_conf = merge_ini_preserving_comments("", distro_sections)

    if distro is not None:
        cat_res = system.run_wsl_command(["-d", distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
        existing_distro_conf = cat_res.stdout if cat_res.returncode == 0 else ""
        merged_distro_conf = merge_ini_preserving_comments(existing_distro_conf, distro_sections)
        distro_changed = merged_distro_conf != existing_distro_conf
        if not dry_run and distro_changed:
            system.run_wsl_command(
                ["-d", distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
                input_text=merged_distro_conf,
            )

    return {
        "dry_run": dry_run,
        "mode": spec.mode,
        "host_memory_bytes": host_memory_bytes,
        "host_memory_gib": host_memory_gib_str,
        "memory_limit_gib": memory_gib,
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_changed": wslconfig_changed,
        "wslconfig_content": merged_wslconfig,
        "distro": distro,
        "distro_changed": distro_changed,
        "distro_wsl_conf_content": merged_distro_conf,
    }


def audit_wsl(env: EnvironmentInfo, wslconfig_path: Path | None = None) -> dict[str, Any]:
    """Audit host WSL2 status, distros, and .wslconfig presence."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    has_wslconfig = target_wslconfig.is_file()
    wslconfig_text = target_wslconfig.read_text(encoding="utf-8") if has_wslconfig else ""

    return {
        "wsl_installed": env.wsl_installed,
        "wsl_version": env.wsl_version,
        "distros": list(env.wsl_distros),
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_exists": has_wslconfig,
        "mirrored_networking": "networkingMode=mirrored" in wslconfig_text.replace(" ", ""),
        "firewall_enabled": "firewall=true" in wslconfig_text.replace(" ", ""),
        "dns_tunneling": "dnsTunneling=true" in wslconfig_text.replace(" ", ""),
    }
