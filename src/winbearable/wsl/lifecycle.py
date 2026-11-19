"""WSL distro lifecycle management and Linux-side baseline application."""

from __future__ import annotations

import glob
import hashlib
from pathlib import Path
from typing import Any

from ..backends.system import SystemBackend
from ..const import DEFAULT_WSL_DISTRO
from .audit import is_windows_credential_helper
from .ini import WslOperationError, validate_dotfiles_repo, validate_wsl_distro_name

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
    validate_wsl_distro_name(distro)
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
    validate_wsl_distro_name(distro)
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
    validate_wsl_distro_name(distro)

    cmd = ["--export", distro, str(output_file)]
    returncode = 0
    sha256_hex: str | None = None
    pruned_files: list[str] = []
    if not dry_run:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        res = system.run_wsl_command(cmd)
        returncode = res.returncode
        if returncode == 0 and output_file.is_file():
            with open(output_file, "rb") as fh:
                sha256_hex = hashlib.file_digest(fh, "sha256").hexdigest()
            output_file.with_suffix(f"{output_file.suffix}.sha256").write_text(
                f"{sha256_hex}  {output_file.name}\n",
                encoding="utf-8",
            )
            if keep_last is not None and keep_last > 0:
                escaped_distro = glob.escape(distro)
                other_tarballs = sorted(
                    (
                        p
                        for p in output_file.parent.glob(f"{escaped_distro}-*.tar")
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
    validate_wsl_distro_name(distro)
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
    validate_wsl_distro_name(distro)
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


def detect_wsl_package_manager(system: SystemBackend, distro: str) -> str:
    """Detect the primary Linux package manager inside a WSL distro."""
    validate_wsl_distro_name(distro)
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
    validate_wsl_distro_name(distro)
    if dotfiles_repo is not None:
        validate_dotfiles_repo(dotfiles_repo)
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
                if is_windows_credential_helper(helper):
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
            if dotfiles_repo.startswith("-"):
                raise WslOperationError(f"Invalid chezmoi dotfiles_repo starting with '-': {dotfiles_repo!r}")
            r4 = system.run_wsl_command(["-d", distro, "--", "chezmoi", "init", "--apply", "--", dotfiles_repo])
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
