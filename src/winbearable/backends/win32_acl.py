"""Windows DACL hardening and verification helpers for state and backup paths."""

from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path
from typing import Any

from ..models import PermissionDeniedError
from .win32_ctypes import get_current_process_user_sid, get_win32_dll

_SDDL_REVISION_1 = 1
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x00000001
_DACL_SECURITY_INFORMATION = 0x00000004
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_VALID_SID_RE = re.compile(r"^S-1-[0-9-]+$")
_ACE_RE = re.compile(r"\(([^)]+)\)")
_BROAD_TRUSTEES: frozenset[str] = frozenset({"WD", "BU", "AU", "AN", "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-7"})
_ALLOWED_OWNER_SIDS: frozenset[str] = frozenset({"S-1-5-18", "S-1-5-32-544"})


def build_private_sddl(user_sid: str) -> str:
    """Build a protected Windows SDDL granting Full Access only to SYSTEM, Administrators, and *user_sid*."""
    if not _VALID_SID_RE.match(user_sid):
        raise ValueError(f"Invalid Windows SID for SDDL: {user_sid!r}")
    return f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid})"


def find_permissive_sddl_trustees(sddl: str, *, allowed_user_sid: str | None = None) -> list[str]:
    """Return any broad-access or foreign Allow trustees (or NULL/empty DACLs) in an SDDL string."""
    upper_sddl = sddl.upper()
    if "NO_ACCESS_CONTROL" in upper_sddl:
        return ["NULL_OR_EMPTY_DACL"]
    aces = _ACE_RE.findall(sddl)
    has_allow_ace = False
    allowed_set = {"SY", "BA", "CO", "OW", "S-1-5-18", "S-1-5-32-544"}
    if allowed_user_sid:
        upper_sid = allowed_user_sid.upper()
        allowed_set.add(upper_sid)
        # ConvertSecurityDescriptorToStringSecurityDescriptorW collapses RID -500 to SDDL alias "LA".
        if upper_sid.endswith("-500"):
            allowed_set.add("LA")

    found: list[str] = []
    for ace_body in aces:
        parts = ace_body.split(";")
        if len(parts) < 6:
            continue
        ace_type = parts[0].strip().upper()
        if ace_type not in {"A", "OA"}:
            continue
        has_allow_ace = True
        trustee = parts[5].strip().upper()
        if (
            trustee in _BROAD_TRUSTEES or (allowed_user_sid is not None and trustee not in allowed_set)
        ) and trustee not in found:
            found.append(trustee)

    if "D:" in upper_sddl and not has_allow_ace:
        return ["NULL_OR_EMPTY_DACL"]
    return found


def apply_windows_private_acl(path: Path, *, windll_override: Any = None) -> bool:
    """Apply a protected owner/SYSTEM/Administrators-only DACL to *path* on Windows."""
    if windll_override is None and sys.platform != "win32":
        return False
    user_sid = get_current_process_user_sid(windll_override)
    if not user_sid:
        return False

    sddl = build_private_sddl(user_sid)
    kernel32 = get_win32_dll("kernel32", windll_override)
    advapi32 = get_win32_dll("advapi32", windll_override)

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_int),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = ctypes.c_int
    advapi32.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = ctypes.c_ulong

    sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, _SDDL_REVISION_1, ctypes.byref(sd), None
    ):
        raise PermissionDeniedError(
            f"Failed to construct private Windows security descriptor for {path}",
            context={"path": str(path)},
        )
    try:
        present = ctypes.c_int(0)
        defaulted = ctypes.c_int(0)
        dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise PermissionDeniedError(
                f"Failed to extract DACL from security descriptor for {path}",
                context={"path": str(path)},
            )
        rc = advapi32.SetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            dacl,
            None,
        )
        if rc != 0:
            raise PermissionDeniedError(
                f"Failed to apply private Windows DACL to {path} (Win32 error {rc})",
                context={"path": str(path), "win32_error": int(rc)},
            )
        return True
    finally:
        if sd.value:
            kernel32.LocalFree(sd)


def verify_windows_private_acl(path: Path, *, windll_override: Any = None) -> None:
    """Verify *path* has a trusted owner and no broad-access ACEs (Everyone/Users/Authenticated Users)."""
    if windll_override is None and sys.platform != "win32":
        return
    if not path.exists():
        return

    kernel32 = get_win32_dll("kernel32", windll_override)
    advapi32 = get_win32_dll("advapi32", windll_override)

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = ctypes.c_ulong
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_void_p,
    ]
    advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int

    owner_sid = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sd = ctypes.c_void_p()
    rc = advapi32.GetNamedSecurityInfoW(
        str(path),
        _SE_FILE_OBJECT,
        _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(owner_sid),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(sd),
    )
    if rc != 0:
        raise PermissionDeniedError(
            f"Unable to inspect Windows security descriptor for {path} (Win32 error {rc})",
            context={"path": str(path), "win32_error": int(rc)},
        )
    try:
        current_sid = get_current_process_user_sid(windll_override)
        sid_ptr = ctypes.c_wchar_p()
        if owner_sid.value and advapi32.ConvertSidToStringSidW(owner_sid, ctypes.byref(sid_ptr)):
            try:
                owner_str = str(sid_ptr.value or "")
            finally:
                if sid_ptr.value:
                    kernel32.LocalFree(sid_ptr)
            allowed_owners = set(_ALLOWED_OWNER_SIDS)
            if current_sid:
                allowed_owners.add(current_sid)
            if owner_str and owner_str not in allowed_owners:
                raise PermissionDeniedError(
                    f"Refusing state path owned by untrusted SID {owner_str}: {path}",
                    context={"path": str(path), "owner_sid": owner_str},
                )

        sddl_ptr = ctypes.c_wchar_p()
        if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(sddl_ptr), None
        ):
            try:
                sddl = str(sddl_ptr.value or "")
            finally:
                if sddl_ptr.value:
                    kernel32.LocalFree(sddl_ptr)
            permissive = find_permissive_sddl_trustees(sddl, allowed_user_sid=current_sid)
            if permissive:
                raise PermissionDeniedError(
                    f"Refusing state path with permissive Windows ACL ({', '.join(permissive)}): {path}",
                    context={"path": str(path), "permissive_trustees": permissive},
                )
    finally:
        if sd.value:
            kernel32.LocalFree(sd)
