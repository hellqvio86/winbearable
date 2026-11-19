"""Read-only WSL2 Windows and Linux-side configuration and credential hygiene audit."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend, is_wsl2
from ..backends.system import NativeSystemBackend, SystemBackend
from ..backends.system_native_cmd import run_subprocess_bounded
from ..const import DEFAULT_WSL_DISTRO
from ..models import EnvironmentInfo
from .config import lint_wsl_conf_lf, probe_distro_wsl_conf
from .ini import (
    detect_wsl_policies,
    get_default_wslconfig_path,
    is_wsl_version_outdated,
    parse_ini_sections,
    validate_wsl_distro_name,
)


def is_windows_credential_helper(helper: str) -> bool:
    low = helper.strip().lower()
    return any(token in low for token in ("wincred", "gcm", ".exe", "/mnt/c/"))


def parse_bool_flag(raw: str | None) -> bool | None:
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


def read_git_system_credential_helpers(git_config_path: Path | None = None) -> list[str]:
    if git_config_path is not None:
        if not git_config_path.is_file():
            return []
        sections = parse_ini_sections(git_config_path.read_text(encoding="utf-8", errors="replace"))
        helper = sections.get("credential", {}).get("helper", "").strip()
        return [helper] if helper else []
    git_exe = NativeSystemBackend._resolve_git_exe()
    if git_exe is None:
        return []
    try:
        res = run_subprocess_bounded(
            [git_exe, "config", "--system", "--get-all", "credential.helper"],
            timeout=5.0,
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


def audit_credential_hygiene(
    git_helpers: list[str],
    ssh_dir: Path | None = None,
    env_vars: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Inspect git credential helpers, ~/.ssh permissions, and Windows SSH agent leakage."""
    issues: list[str] = []
    win_helpers = [h for h in git_helpers if is_windows_credential_helper(h)]
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
    conf_sections = parse_ini_sections(wsl_conf.read_text(encoding="utf-8", errors="replace")) if has_wsl_conf else {}
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

    git_helpers = read_git_system_credential_helpers(git_config_path)
    credential_hygiene = audit_credential_hygiene(git_helpers, ssh_dir=ssh_dir, env_vars=env_vars)
    git_isolated = len(credential_hygiene["windows_git_helpers"]) == 0

    return {
        "is_linux": True,
        "is_wsl2": is_wsl2()
        if platform_override is None
        else ("WSL_DISTRO_NAME" in os.environ or "WSL_INTEROP" in os.environ),
        "distro": os.environ.get("WSL_DISTRO_NAME"),
        "wsl_conf_path": str(wsl_conf),
        "wsl_conf_exists": has_wsl_conf,
        "automount_enabled": parse_bool_flag(automount_sec.get("enabled")),
        "interop_enabled": parse_bool_flag(interop_sec.get("enabled")),
        "append_windows_path": parse_bool_flag(interop_sec.get("appendWindowsPath")),
        "systemd_configured": parse_bool_flag(boot_sec.get("systemd")),
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
            first_col = re.split(r"\s{2,}", cleaned[1:].strip(), maxsplit=1)[0].strip()
            if first_col:
                return first_col
    return None


_DISTRO_EOL_VERSIONS: dict[str, set[str]] = {
    "ubuntu": {"18.04", "20.04", "22.10", "23.04", "23.10"},
    "debian": {"10", "11"},
    "fedora": {"38", "39", "40"},
}


def deep_audit_wsl_distro(system: SystemBackend, distro: str) -> dict[str, Any]:
    """Run read-only deep exposure checks inside a WSL2 distro via fixed-argv commands."""
    validate_wsl_distro_name(distro)
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
    sections = parse_ini_sections(wslconfig_text) if has_wslconfig else {}
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
