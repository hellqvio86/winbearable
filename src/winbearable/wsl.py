"""Non-destructive .wslconfig and /etc/wsl.conf management and 75% RAM sizing."""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .backends.registry import is_wsl2
from .backends.system import GIB_BYTES, SystemBackend
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


def merge_ini_preserving_comments(existing_text: str, desired_sections: dict[str, dict[str, str]]) -> str:
    """Merge desired INI sections/keys into existing_text while preserving comments and custom keys."""
    lines = existing_text.splitlines() if existing_text else []
    remaining_sections: dict[str, dict[str, str]] = {sec: dict(kv_map) for sec, kv_map in desired_sections.items()}

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


def _atomic_write_text(target_path: Path, content: str) -> Path | None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path: Path | None = None
    existing_mode: int | None = None
    if target_path.is_file():
        existing_mode = stat.S_IMODE(target_path.stat().st_mode)
        backup_path = target_path.with_suffix(f"{target_path.suffix}.bak")
        shutil.copy2(target_path, backup_path)

    fd, temp_path_str = tempfile.mkstemp(
        prefix=f"{target_path.name}.",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
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

    desired_wslconfig_sections = build_wslconfig_sections(spec, host_memory_bytes)
    merged_wslconfig = merge_ini_preserving_comments(existing_wslconfig, desired_wslconfig_sections)
    wslconfig_changed = merged_wslconfig != existing_wslconfig
    backup_path: Path | None = None

    if not dry_run and wslconfig_changed:
        backup_path = _atomic_write_text(target_wslconfig, merged_wslconfig)
        verified_text = target_wslconfig.read_text(encoding="utf-8")
        if verified_text != merged_wslconfig:
            raise WslOperationError(f"Verification failed after writing {target_wslconfig}.")

    distro_sections = build_distro_wsl_conf_sections(spec)
    distro_changed = False
    merged_distro_conf = merge_ini_preserving_comments("", distro_sections)

    if distro is not None:
        cat_res = system.run_wsl_command(["-d", distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
        existing_distro_conf = cat_res.stdout if cat_res.returncode == 0 else ""
        merged_distro_conf = merge_ini_preserving_comments(existing_distro_conf, distro_sections)
        distro_changed = merged_distro_conf != existing_distro_conf
        if not dry_run and distro_changed:
            write_res = system.run_wsl_command(
                ["-d", distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
                input_text=merged_distro_conf,
            )
            if write_res.returncode != 0:
                raise WslOperationError(f"Failed to write /etc/wsl.conf in '{distro}': {write_res.stderr}")
            verify_res = system.run_wsl_command(["-d", distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
            if verify_res.returncode != 0 or verify_res.stdout != merged_distro_conf:
                raise WslOperationError(f"Verification failed after writing /etc/wsl.conf in '{distro}'.")

    return {
        "dry_run": dry_run,
        "mode": spec.mode,
        "host_memory_bytes": host_memory_bytes,
        "host_memory_gib": host_memory_gib_str,
        "memory_limit_gib": memory_gib,
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_backup_path": str(backup_path) if backup_path is not None else None,
        "wslconfig_changed": wslconfig_changed,
        "wslconfig_content": merged_wslconfig,
        "distro": distro,
        "distro_changed": distro_changed,
        "distro_wsl_conf_content": merged_distro_conf,
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
    git_exe = shutil.which("git")
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
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError):
        return []


def audit_linux_side(
    wsl_conf_path: Path | None = None,
    sysctl_conf_path: Path | None = None,
    proc_sys_root: Path | None = None,
    systemd_marker_path: Path | None = None,
    git_config_path: Path | None = None,
    platform_override: str | None = None,
) -> dict[str, Any]:
    """Audit Linux-side WSL2 settings: /etc/wsl.conf, sysctl baseline, systemd, and git credential isolation."""
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
    }
    sysctl_values = {key: _read_proc_sys_value(proc_root, rel_path) for key, (rel_path, _) in expected_sysctl.items()}
    sysctl_applied = all(sysctl_values.get(key) == expected for key, (_, expected) in expected_sysctl.items())

    git_helpers = _read_git_system_credential_helpers(git_config_path)
    git_isolated = not any(token in helper.lower() for helper in git_helpers for token in ("wincred", "gcm", ".exe"))

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
    }


def audit_wsl(env: EnvironmentInfo, wslconfig_path: Path | None = None) -> dict[str, Any]:
    """Audit host WSL2 status, distros, .wslconfig presence, and Linux-side configuration."""
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    has_wslconfig = target_wslconfig.is_file()
    wslconfig_text = target_wslconfig.read_text(encoding="utf-8") if has_wslconfig else ""
    sections = _parse_ini_sections(wslconfig_text) if has_wslconfig else {}
    wsl2_sec = sections.get("wsl2", {})

    return {
        "wsl_installed": env.wsl_installed,
        "wsl_version": env.wsl_version,
        "distros": list(env.wsl_distros),
        "wslconfig_path": str(target_wslconfig),
        "wslconfig_exists": has_wslconfig,
        "mirrored_networking": wsl2_sec.get("networkingMode", "").lower() == "mirrored",
        "firewall_enabled": wsl2_sec.get("firewall", "").lower() == "true",
        "dns_tunneling": wsl2_sec.get("dnsTunneling", "").lower() == "true",
        "linux": audit_linux_side(),
    }


WSL_LINUX_SYSCTL_CONF = """# Managed by winbearable (wb wsl baseline)
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
"""


def install_wsl_distro(
    system: SystemBackend,
    distro: str,
    web_download: bool = False,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Install a WSL2 distribution via wsl.exe --install (with optional --web-download Store bypass)."""
    cmd = ["--install", "-d", distro]
    if web_download:
        cmd.append("--web-download")
    returncode = 0
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "web_download": web_download,
        "command": ["wsl.exe", *cmd],
        "returncode": returncode,
    }


def export_wsl_distro(
    system: SystemBackend,
    distro: str,
    output_file: Path,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Export a WSL2 distribution to a backup tarball via wsl.exe --export."""
    cmd = ["--export", distro, str(output_file)]
    returncode = 0
    if not dry_run:
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
    return {
        "dry_run": dry_run,
        "distro": distro,
        "output_file": str(output_file),
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


def apply_wsl_linux_baseline(
    system: SystemBackend,
    distro: str,
    dotfiles_repo: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Configure Linux-side sysctl baseline, isolate git credential helper, and optional chezmoi dotfiles."""
    sysctl_path = "/etc/sysctl.d/99-winbearable-wsl.conf"
    steps: list[str] = [
        f"Write {sysctl_path} (kptr_restrict=2, dmesg_restrict=1, rp_filter=1)",
        "Reload sysctl settings via sysctl --system",
        "Isolate git credential helper from Windows Credential Manager",
    ]
    if dotfiles_repo:
        steps.append(f"Apply dotfiles via chezmoi init --apply {dotfiles_repo}")

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
        r3 = system.run_wsl_command(
            ["-d", distro, "-u", "root", "--", "git", "config", "--system", "--unset-all", "credential.helper"]
        )
        if r3.returncode not in (0, 5):  # git config --unset-all returns 5 if key was absent
            raise WslOperationError(f"Failed to isolate git credential.helper in '{distro}': {r3.stderr}")
        if dotfiles_repo:
            r4 = system.run_wsl_command(["-d", distro, "--", "chezmoi", "init", "--apply", dotfiles_repo])
            if r4.returncode != 0:
                raise WslOperationError(f"Failed to apply chezmoi dotfiles in '{distro}': {r4.stderr}")

    return {
        "dry_run": dry_run,
        "distro": distro,
        "sysctl_path": sysctl_path,
        "sysctl_content": WSL_LINUX_SYSCTL_CONF,
        "dotfiles_repo": dotfiles_repo,
        "steps": steps,
    }
