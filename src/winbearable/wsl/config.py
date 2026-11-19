"""Transactional WSL config probing, planning, applying, and rollback."""

from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import WslConfigSpec
from .ini import (
    WslOperationError,
    atomic_write_text,
    build_distro_wsl_conf_sections,
    build_wslconfig_sections,
    calculate_wsl_memory_gib,
    create_backup_file,
    format_host_memory_gib,
    get_default_wslconfig_path,
    merge_ini_preserving_comments,
    validate_wsl_distro_name,
)


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
    validate_wsl_distro_name(distro)
    try:
        test_res = system.run_wsl_command(
            ["-d", distro, "-u", "root", "--", "sh", "-c", "test -e /etc/wsl.conf; echo WB_RC=$?"]
        )
    except (WslOperationError, OSError, TimeoutError) as exc:
        return WslDistroConfProbe(status="error", content="", evidence=str(exc))

    test_stderr = (test_res.stderr or "").strip()
    if "WB_RC=1" in test_res.stdout and (test_res.returncode == 0 or not test_stderr):
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
    installed_wsl_version: str | None = None,
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
    desired_wslconfig_sections = build_wslconfig_sections(
        spec, host_memory_bytes, installed_wsl_version=installed_wsl_version, warnings=warnings
    )
    merged_wslconfig = merge_ini_preserving_comments(existing_wslconfig, desired_wslconfig_sections)
    wslconfig_changed = merged_wslconfig != existing_wslconfig

    backup_path: Path | None = None
    if create_host_backup and wslconfig_changed:
        backup_path = create_backup_file(target_wslconfig, backup_dir=backup_dir)

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
    atomic_write_text(plan.target_wslconfig, plan.merged_wslconfig, create_backup=plan.backup_path is None)
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


def _rollback_distro_wsl_conf(distro_plan: PreparedWslDistroPlan, system: SystemBackend) -> None:
    """Best-effort restore of /etc/wsl.conf if post-write verification fails."""
    if distro_plan.probe.status == "exists":
        system.run_wsl_command(
            ["-d", distro_plan.distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
            input_text=distro_plan.probe.content,
        )
    elif distro_plan.probe.status == "missing":
        system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "rm", "-f", "/etc/wsl.conf"])


def apply_distro_wsl_conf(distro_plan: PreparedWslDistroPlan, system: SystemBackend) -> None:
    """Atomically write and byte-verify /etc/wsl.conf (LF-only) for a single prepared distro."""
    if not distro_plan.changed:
        return
    lf_content = distro_plan.merged_content.replace("\r\n", "\n").replace("\r", "\n")
    expected_sha256 = hashlib.sha256(lf_content.encode("utf-8")).hexdigest()
    if getattr(system, "is_simulated", False):
        write_res = system.run_wsl_command(
            ["-d", distro_plan.distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
            input_text=lf_content,
        )
        if write_res.returncode != 0:
            raise WslOperationError(f"Failed to write /etc/wsl.conf in '{distro_plan.distro}': {write_res.stderr}")
    else:
        tmp_path = "/etc/wsl.conf.wb.tmp"
        write_res = system.run_wsl_command(
            ["-d", distro_plan.distro, "-u", "root", "--", "tee", tmp_path],
            input_text=lf_content,
        )
        if write_res.returncode != 0:
            system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "rm", "-f", tmp_path])
            raise WslOperationError(f"Failed to write {tmp_path} in '{distro_plan.distro}': {write_res.stderr}")

        mv_res = system.run_wsl_command(
            ["-d", distro_plan.distro, "-u", "root", "--", "mv", "-f", tmp_path, "/etc/wsl.conf"]
        )
        if mv_res.returncode != 0:
            system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "rm", "-f", tmp_path])
            raise WslOperationError(
                f"Failed to move {tmp_path} to /etc/wsl.conf in '{distro_plan.distro}': {mv_res.stderr}"
            )

    sha_res = system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "sha256sum", "/etc/wsl.conf"])
    sha_tokens = sha_res.stdout.strip().split() if sha_res.returncode == 0 else []
    if sha_tokens and len(sha_tokens[0]) == 64 and sha_tokens[0].lower() != expected_sha256:
        _rollback_distro_wsl_conf(distro_plan, system)
        raise WslOperationError(
            f"SHA-256 verification failed after writing /etc/wsl.conf in '{distro_plan.distro}' "
            f"(expected {expected_sha256}, got {sha_tokens[0].lower()})."
        )

    verify_res = system.run_wsl_command(["-d", distro_plan.distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
    if verify_res.returncode != 0 or "\r" in verify_res.stdout or verify_res.stdout != lf_content:
        _rollback_distro_wsl_conf(distro_plan, system)
        raise WslOperationError(f"Verification failed after writing /etc/wsl.conf in '{distro_plan.distro}'.")


def plan_or_apply_wsl(
    spec: WslConfigSpec,
    system: SystemBackend,
    wslconfig_path: Path | None = None,
    distro: str | None = None,
    dry_run: bool = True,
    installed_wsl_version: str | None = None,
) -> dict[str, Any]:
    """Plan or apply .wslconfig (sizing memory to 75% of host RAM) and per-distro /etc/wsl.conf."""
    if distro is not None:
        validate_wsl_distro_name(distro)
    target_wslconfig = wslconfig_path or get_default_wslconfig_path()
    had_wslconfig = target_wslconfig.is_file()
    existing_wslconfig = target_wslconfig.read_text(encoding="utf-8").lstrip("\ufeff") if had_wslconfig else ""

    host_memory_bytes = system.get_total_memory_bytes()
    host_memory_gib_str = format_host_memory_gib(host_memory_bytes)
    memory_gib = spec.memory_gb if spec.memory_gb is not None else calculate_wsl_memory_gib(host_memory_bytes)

    warnings: list[str] = []
    desired_wslconfig_sections = build_wslconfig_sections(
        spec, host_memory_bytes, installed_wsl_version=installed_wsl_version, warnings=warnings
    )
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
        backup_path = atomic_write_text(target_wslconfig, merged_wslconfig)
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
            elif wslconfig_changed and not had_wslconfig:
                target_wslconfig.unlink(missing_ok=True)
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
