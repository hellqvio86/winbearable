"""Native Windows security policy, event log, firewall, fsutil, powercfg, git, and ACL helpers."""

from __future__ import annotations

import contextlib
import csv
import ctypes
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..const import HIVE_HKLM
from .registry import RegistryBackend
from .system_native_cmd import is_user_writable_binary, resolve_git_exe, sys32_exe
from .system_protocol import CommandResult
from .win32_ctypes import get_current_process_user_sid
from .win32_fs import is_reparse_or_symlink

_GUID_RE = re.compile(r"^\{?[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}?$")
_FW_GROUP_RE = re.compile(r"^@[A-Za-z0-9_.-]+,-\d+$")
_GIT_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+$")


def _is_safe_arg(val: str) -> bool:
    return bool(val) and not val.startswith(("-", "/")) and not any(ch in val for ch in ("\r", "\n", "\x00"))


def _ensure_safe_backup_target(path: Path) -> bool:
    return not is_reparse_or_symlink(path) and not any(is_reparse_or_symlink(p) for p in path.parents)


def get_auditpol_subcategory(run_cmd: Callable[..., CommandResult], platform_name: str, guid: str) -> str | None:
    if platform_name != "win32" or not _GUID_RE.fullmatch(guid):
        return None
    guid_arg = guid if guid.startswith("{") else f"{{{guid}}}"
    res = run_cmd([sys32_exe("auditpol.exe"), "/get", f"/subcategory:{guid_arg}", "/r", "/v"])
    if res.returncode != 0:
        return None
    value_map = {"0": "No Auditing", "1": "Success", "2": "Failure", "3": "Success and Failure"}
    for line in res.stdout.splitlines():
        if guid_arg.lower() in line.lower():
            parts = [p.strip().strip('"') for p in line.split(",")]
            if parts and parts[-1] in value_map:
                return value_map[parts[-1]]
            if len(parts) >= 5:
                return parts[4]
    return None


def set_auditpol_subcategory(
    run_cmd: Callable[..., CommandResult], platform_name: str, guid: str, success: bool, failure: bool
) -> bool:
    if platform_name != "win32" or not _GUID_RE.fullmatch(guid):
        return False
    guid_arg = guid if guid.startswith("{") else f"{{{guid}}}"
    succ_flag = "enable" if success else "disable"
    fail_flag = "enable" if failure else "disable"
    res = run_cmd(
        [
            sys32_exe("auditpol.exe"),
            "/set",
            f"/subcategory:{guid_arg}",
            f"/success:{succ_flag}",
            f"/failure:{fail_flag}",
        ]
    )
    return res.returncode == 0


def backup_auditpol(run_cmd: Callable[..., CommandResult], platform_name: str, output_csv: Path) -> bool:
    if platform_name != "win32" or not _ensure_safe_backup_target(output_csv):
        return False
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if output_csv.exists():
        output_csv.unlink()
    return run_cmd([sys32_exe("auditpol.exe"), "/backup", f"/file:{output_csv}"]).returncode == 0


def restore_auditpol(run_cmd: Callable[..., CommandResult], platform_name: str, input_csv: Path) -> bool:
    if platform_name != "win32" or not input_csv.is_file():
        return False
    return run_cmd([sys32_exe("auditpol.exe"), "/restore", f"/file:{input_csv}"]).returncode == 0


def get_event_log_config(
    run_cmd: Callable[..., CommandResult], platform_name: str, channel: str
) -> tuple[bool | None, int | None]:
    if platform_name != "win32" or not _is_safe_arg(channel):
        return None, None
    res = run_cmd([sys32_exe("wevtutil.exe"), "gl", channel, "/f:xml"])
    if res.returncode != 0:
        return None, None
    out = res.stdout
    en_attr = re.search(r'<channel\b[^>]*\benabled="(true|false)"', out, re.IGNORECASE)
    en_tag = re.search(r"<enabled>\s*(true|false)\s*</enabled>", out, re.IGNORECASE)
    enabled: bool | None = None
    if en_attr is not None:
        enabled = en_attr.group(1).lower() == "true"
    elif en_tag is not None:
        enabled = en_tag.group(1).lower() == "true"
    sz_match = re.search(r"<maxSize>\s*(\d+)\s*</maxSize>", out, re.IGNORECASE)
    max_size = int(sz_match.group(1)) if sz_match is not None else None
    return enabled, max_size


def set_event_log_config(
    run_cmd: Callable[..., CommandResult],
    platform_name: str,
    channel: str,
    enabled: bool | None = None,
    max_size_bytes: int | None = None,
) -> bool:
    if platform_name != "win32" or not _is_safe_arg(channel):
        return False
    cmd = [sys32_exe("wevtutil.exe"), "sl", channel]
    if enabled is not None:
        cmd.append(f"/e:{'true' if enabled else 'false'}")
    if max_size_bytes is not None:
        cmd.append(f"/ms:{max_size_bytes}")
    return run_cmd(cmd).returncode == 0


def is_firewall_group_enabled(registry: RegistryBackend, group_resource_id: str) -> bool | None:
    fw_rules_key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
    target_embed = f"embedctxt={group_resource_id.lower()}"
    for _, vdata, _ in registry.list_values(HIVE_HKLM, fw_rules_key):
        if isinstance(vdata, str):
            low_val = vdata.lower()
            if target_embed in low_val and "active=true" in low_val:
                return True
    return False


def set_firewall_group_enabled(
    run_cmd: Callable[..., CommandResult], platform_name: str, group_resource_id: str, enabled: bool
) -> bool:
    if platform_name != "win32" or not _FW_GROUP_RE.fullmatch(group_resource_id):
        return False
    en_str = "yes" if enabled else "no"
    res = run_cmd(
        [
            sys32_exe("netsh.exe"),
            "advfirewall",
            "firewall",
            "set",
            "rule",
            f"group={group_resource_id}",
            "new",
            f"enable={en_str}",
        ]
    )
    return res.returncode == 0


def export_firewall_policy(run_cmd: Callable[..., CommandResult], platform_name: str, output_wfw: Path) -> bool:
    if platform_name != "win32" or not _ensure_safe_backup_target(output_wfw):
        return False
    output_wfw.parent.mkdir(parents=True, exist_ok=True)
    if output_wfw.exists():
        output_wfw.unlink()
    return run_cmd([sys32_exe("netsh.exe"), "advfirewall", "export", str(output_wfw)]).returncode == 0


def import_firewall_policy(run_cmd: Callable[..., CommandResult], platform_name: str, input_wfw: Path) -> bool:
    if platform_name != "win32" or not input_wfw.is_file():
        return False
    return run_cmd([sys32_exe("netsh.exe"), "advfirewall", "import", str(input_wfw)]).returncode == 0


def is_dir_case_sensitive(
    run_cmd: Callable[..., CommandResult], platform_name: str, directory: str, k32: Any | None
) -> bool | None:
    if platform_name != "win32":
        return None
    res = run_cmd([sys32_exe("fsutil.exe"), "file", "queryCaseSensitiveInfo", directory])
    if res.returncode != 0:
        return None
    low = res.stdout.strip().lower()
    if "enabled" in low or low.endswith("1."):
        return True
    if "disabled" in low or low.endswith("0."):
        return False
    if k32 is not None:
        try:
            with contextlib.suppress(AttributeError, TypeError):
                k32.CreateFileW.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_ulong,
                    ctypes.c_ulong,
                    ctypes.c_void_p,
                    ctypes.c_ulong,
                    ctypes.c_ulong,
                    ctypes.c_void_p,
                ]
                k32.CreateFileW.restype = ctypes.c_void_p
                k32.GetFileInformationByHandleEx.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_int,
                    ctypes.c_void_p,
                    ctypes.c_ulong,
                ]
                k32.GetFileInformationByHandleEx.restype = ctypes.c_int
                k32.CloseHandle.argtypes = [ctypes.c_void_p]
                k32.CloseHandle.restype = ctypes.c_int
            handle = k32.CreateFileW(directory, 0x80, 7, None, 3, 0x02000000, None)
            invalid = ctypes.c_void_p(-1).value
            if handle not in (None, 0, invalid, -1):
                try:
                    flags = ctypes.c_ulong(0)
                    if k32.GetFileInformationByHandleEx(
                        ctypes.c_void_p(handle), 23, ctypes.byref(flags), ctypes.sizeof(flags)
                    ):
                        return bool(flags.value & 1)
                finally:
                    k32.CloseHandle(ctypes.c_void_p(handle))
        except OSError, AttributeError, TypeError, ctypes.ArgumentError:
            pass
    return None


def set_dir_case_sensitive(
    run_cmd: Callable[..., CommandResult], platform_name: str, directory: str, enabled: bool
) -> bool:
    if platform_name != "win32":
        return False
    dir_path = Path(directory)
    if not enabled and dir_path.is_dir() and any(dir_path.iterdir()):
        return False
    dir_path.mkdir(parents=True, exist_ok=True)
    flag = "enable" if enabled else "disable"
    return run_cmd([sys32_exe("fsutil.exe"), "file", "setCaseSensitiveInfo", directory, flag]).returncode == 0


def get_git_global_config(
    run_cmd: Callable[..., CommandResult],
    key: str,
    git_exe_resolver: Callable[[], str | None] = resolve_git_exe,
    *,
    is_admin: bool = False,
) -> str | None:
    if not _GIT_KEY_RE.fullmatch(key):
        return None
    git_exe = git_exe_resolver()
    if git_exe is None or (is_admin and is_user_writable_binary(git_exe)):
        return None
    res = run_cmd([git_exe, "config", "--global", "--get", "--", key])
    if res.returncode != 0:
        return None
    return res.stdout.strip()


def set_git_global_config(
    run_cmd: Callable[..., CommandResult],
    key: str,
    value: str | None,
    git_exe_resolver: Callable[[], str | None] = resolve_git_exe,
    *,
    is_admin: bool = False,
) -> bool:
    if not _GIT_KEY_RE.fullmatch(key):
        return False
    git_exe = git_exe_resolver()
    if git_exe is None or (is_admin and is_user_writable_binary(git_exe)):
        return False
    if value is None:
        return run_cmd([git_exe, "config", "--global", "--unset", "--", key]).returncode in (0, 5)
    return run_cmd([git_exe, "config", "--global", "--", key, value]).returncode == 0


def get_current_user_sid(run_cmd: Callable[..., CommandResult], platform_name: str) -> str | None:
    if platform_name != "win32":
        return None
    native_sid = get_current_process_user_sid()
    if native_sid is not None:
        return native_sid
    res = run_cmd([sys32_exe("whoami.exe"), "/user", "/fo", "csv", "/nh"])
    if res.returncode != 0:
        return None
    for row in csv.reader(res.stdout.splitlines()):
        if len(row) >= 2 and row[1].strip().startswith("S-1-"):
            return row[1].strip()
    return None


def is_sddl_restricted_to_sid(sddl: str, owner_sid: str) -> bool:
    """Return True iff the SDDL DACL is protected (D:P) and allows only owner_sid (or OW)."""
    dacl_idx = sddl.find("D:")
    if dacl_idx == -1:
        return False
    dacl_tail = sddl[dacl_idx + 2 :]
    sacl_idx = dacl_tail.find("S:")
    dacl_body = dacl_tail[:sacl_idx] if sacl_idx != -1 else dacl_tail
    flags = dacl_body.split("(", 1)[0]
    if "P" not in flags:
        return False
    aces = re.findall(r"\(([^)]+)\)", dacl_body)
    if not aces:
        return False
    has_owner_allow = False
    for ace in aces:
        parts = ace.split(";")
        if len(parts) < 6:
            return False
        ace_type = parts[0].strip().upper()
        trustee = parts[5].strip()
        if ace_type in {"A", "OA"}:
            if trustee not in {owner_sid, "OW"}:
                return False
            has_owner_allow = True
    return has_owner_allow


def is_ssh_acl_restricted(
    run_cmd: Callable[..., CommandResult],
    platform_name: str,
    path_str: str,
    sid_resolver: Callable[[], str | None] | None = None,
) -> bool:
    expanded = os.path.expandvars(os.path.expanduser(path_str))
    target = Path(expanded)
    if not target.exists():
        return True
    if platform_name != "win32":
        return False
    owner_sid = sid_resolver() if sid_resolver is not None else get_current_user_sid(run_cmd, platform_name)
    if owner_sid is not None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            acl_file = Path(tmp_dir) / "acl.sddl"
            save_res = run_cmd([sys32_exe("icacls.exe"), str(target), "/save", str(acl_file)])
            if save_res.returncode == 0 and acl_file.is_file():
                raw_bytes = acl_file.read_bytes()
                sddl_text = (
                    raw_bytes.decode("utf-16-le", errors="replace")
                    if b"\x00" in raw_bytes or raw_bytes.startswith(b"\xff\xfe")
                    else raw_bytes.decode("utf-8", errors="replace")
                ).lstrip("\ufeff")
                sddl_lines = [ln.strip() for ln in sddl_text.splitlines() if "D:" in ln]
                if sddl_lines:
                    return all(is_sddl_restricted_to_sid(ln, owner_sid) for ln in sddl_lines)
    return False


def backup_acl(run_cmd: Callable[..., CommandResult], platform_name: str, path_str: str, backup_file: Path) -> bool:
    if platform_name != "win32" or not _ensure_safe_backup_target(backup_file):
        return False
    target = Path(os.path.expandvars(os.path.expanduser(path_str)))
    if not target.exists():
        return True
    backup_file.parent.mkdir(parents=True, exist_ok=True)
    return run_cmd([sys32_exe("icacls.exe"), str(target), "/save", str(backup_file)]).returncode == 0


def restore_acl(run_cmd: Callable[..., CommandResult], platform_name: str, path_str: str, backup_file: Path) -> bool:
    if platform_name != "win32" or not backup_file.is_file():
        return False
    target = Path(os.path.expandvars(os.path.expanduser(path_str)))
    if not target.exists():
        return False
    return run_cmd([sys32_exe("icacls.exe"), str(target.parent), "/restore", str(backup_file)]).returncode == 0


def restrict_acl_to_current_user(
    run_cmd: Callable[..., CommandResult],
    platform_name: str,
    path_str: str,
    sid_resolver: Callable[[], str | None] | None = None,
) -> bool:
    if platform_name != "win32":
        return False
    target = Path(os.path.expandvars(os.path.expanduser(path_str)))
    if not target.exists():
        return True
    owner_sid = sid_resolver() if sid_resolver is not None else get_current_user_sid(run_cmd, platform_name)
    if not owner_sid:
        return False
    principal = f"*{owner_sid}"
    res = run_cmd(
        [
            sys32_exe("icacls.exe"),
            str(target),
            "/inheritance:r",
            "/grant:r",
            f"{principal}:(OI)(CI)F" if target.is_dir() else f"{principal}:F",
        ]
    )
    return res.returncode == 0


class NativeSecMixin:
    """Mixin delegating auditpol, wevtutil, firewall, fsutil, and ACL operations for NativeSystemBackend."""

    _platform: str

    def _run_native_cmd(self, args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        raise NotImplementedError

    def _get_dll(self, name: str) -> Any | None:
        raise NotImplementedError

    def get_auditpol_subcategory(self, subcategory_guid: str) -> str | None:
        return get_auditpol_subcategory(self._run_native_cmd, self._platform, subcategory_guid)

    def set_auditpol_subcategory(self, subcategory_guid: str, success: bool, failure: bool) -> bool:
        return set_auditpol_subcategory(self._run_native_cmd, self._platform, subcategory_guid, success, failure)

    def backup_auditpol(self, output_csv: Path) -> bool:
        return backup_auditpol(self._run_native_cmd, self._platform, output_csv)

    def restore_auditpol(self, input_csv: Path) -> bool:
        return restore_auditpol(self._run_native_cmd, self._platform, input_csv)

    def get_event_log_config(self, channel: str) -> tuple[bool | None, int | None]:
        return get_event_log_config(self._run_native_cmd, self._platform, channel)

    def set_event_log_config(
        self,
        channel: str,
        enabled: bool | None = None,
        max_size_bytes: int | None = None,
    ) -> bool:
        return set_event_log_config(self._run_native_cmd, self._platform, channel, enabled, max_size_bytes)

    def is_firewall_group_enabled(self, registry: Any, group_resource_id: str) -> bool | None:
        return is_firewall_group_enabled(registry, group_resource_id)

    def set_firewall_group_enabled(self, group_resource_id: str, enabled: bool) -> bool:
        return set_firewall_group_enabled(self._run_native_cmd, self._platform, group_resource_id, enabled)

    def export_firewall_policy(self, output_wfw: Path) -> bool:
        return export_firewall_policy(self._run_native_cmd, self._platform, output_wfw)

    def import_firewall_policy(self, input_wfw: Path) -> bool:
        return import_firewall_policy(self._run_native_cmd, self._platform, input_wfw)

    def is_dir_case_sensitive(self, directory: str) -> bool | None:
        return is_dir_case_sensitive(self._run_native_cmd, self._platform, directory, self._get_dll("kernel32"))

    def set_dir_case_sensitive(self, directory: str, enabled: bool) -> bool:
        return set_dir_case_sensitive(self._run_native_cmd, self._platform, directory, enabled)

    def _get_current_user_sid(self) -> str | None:
        return get_current_user_sid(self._run_native_cmd, self._platform)

    _is_sddl_restricted_to_sid = staticmethod(is_sddl_restricted_to_sid)

    def is_ssh_acl_restricted(self, path_str: str) -> bool:
        return is_ssh_acl_restricted(self._run_native_cmd, self._platform, path_str, self._get_current_user_sid)

    def backup_acl(self, path_str: str, backup_file: Path) -> bool:
        return backup_acl(self._run_native_cmd, self._platform, path_str, backup_file)

    def restore_acl(self, path_str: str, backup_file: Path) -> bool:
        return restore_acl(self._run_native_cmd, self._platform, path_str, backup_file)

    def restrict_acl_to_current_user(self, path_str: str) -> bool:
        return restrict_acl_to_current_user(self._run_native_cmd, self._platform, path_str, self._get_current_user_sid)
