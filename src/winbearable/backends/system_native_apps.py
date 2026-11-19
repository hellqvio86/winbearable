"""OneDrive, Winget, and VS Code extension methods for NativeSystemBackend."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..models import OperationOutcome, OperationStatus
from .system_native_cmd import is_user_writable_binary
from .system_protocol import CommandResult


class NativeAppMixin:
    """Mixin providing OneDrive, Winget, and VS Code extension operations for NativeSystemBackend."""

    _platform: str
    _setup_candidates: tuple[str, ...]
    _winget_installed_cache: dict[str, bool]
    last_outcome: OperationOutcome | None

    _is_user_writable_binary = staticmethod(is_user_writable_binary)

    def _run_native_cmd(self, args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        raise NotImplementedError

    def is_process_running(self, process_name: str) -> bool:
        raise NotImplementedError

    def _resolve_winget_exe(self) -> str:
        raise NotImplementedError

    def _resolve_code_cmd(self) -> str:
        raise NotImplementedError

    def _check_is_admin(self) -> bool:
        raise NotImplementedError

    def is_onedrive_installed(self) -> bool:
        if self._platform != "win32":
            return False
        local_app = os.environ.get("LOCALAPPDATA", "")
        prog_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        prog_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        binary_candidates = [
            Path(local_app) / "Microsoft" / "OneDrive" / "OneDrive.exe" if local_app else None,
            Path(prog_files) / "Microsoft OneDrive" / "OneDrive.exe",
            Path(prog_x86) / "Microsoft OneDrive" / "OneDrive.exe",
        ]
        if any(cand is not None and cand.is_file() for cand in binary_candidates):
            return True
        return self.is_process_running("OneDrive.exe")

    def uninstall_onedrive_client(self) -> bool:
        if self._platform != "win32":
            return False
        for candidate in self._setup_candidates:
            if Path(candidate).is_file():
                res = self._run_native_cmd([candidate, "/uninstall"])
                if res.returncode != 0:
                    return False
                return not self.is_onedrive_installed()
        return False

    def is_winget_package_installed(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        cache_key = package_id.lower()
        if cache_key in self._winget_installed_cache:
            return self._winget_installed_cache[cache_key]
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "list",
                "--id",
                package_id,
                "--exact",
                "--accept-source-agreements",
            ],
            timeout=60.0,
        )
        installed = res.returncode == 0 and bool(
            re.search(rf"(?m)(?:^|\s){re.escape(package_id)}(?:\s|$)", res.stdout, re.IGNORECASE)
        )
        self._winget_installed_cache[cache_key] = installed
        return installed

    def install_winget_package(
        self,
        package_id: str,
        scope: str = "user",
        vscode_extensions: tuple[str, ...] = (),
    ) -> bool:
        if self._platform != "win32":
            return False
        self._winget_installed_cache.pop(package_id.lower(), None)
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "install",
                "--id",
                package_id,
                "--source",
                "winget",
                "--exact",
                "--scope",
                scope,
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
            timeout=300.0,
        )
        if res.returncode != 0 or not self.is_winget_package_installed(package_id):
            return False
        for ext in vscode_extensions:
            if not self.install_vscode_extension(ext):
                return False
        self._winget_installed_cache[package_id.lower()] = True
        return True

    def _guard_elevated_code_cmd(self) -> str | None:
        code_cmd = self._resolve_code_cmd()
        if self._check_is_admin() and self._is_user_writable_binary(code_cmd):
            self.last_outcome = OperationOutcome(
                status=OperationStatus.ACCESS_DENIED,
                message=f"Refusing to execute user-writable '{code_cmd}' while elevated.",
                command=(code_cmd,),
            )
            return None
        return code_cmd

    def install_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        ext_res = self._run_native_cmd([code_cmd, "--install-extension", extension_id, "--force"], timeout=120.0)
        return ext_res.returncode == 0

    def uninstall_winget_package(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        self._winget_installed_cache.pop(package_id.lower(), None)
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "uninstall",
                "--id",
                package_id,
                "--exact",
                "--accept-source-agreements",
            ]
        )
        ok = res.returncode == 0
        if ok:
            self._winget_installed_cache[package_id.lower()] = False
        return ok

    def is_vscode_extension_installed(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        res = self._run_native_cmd([code_cmd, "--list-extensions"], timeout=30.0)
        if res.returncode != 0:
            return False
        target = extension_id.lower()
        return any(line.strip().lower() == target for line in res.stdout.splitlines())

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        res = self._run_native_cmd([code_cmd, "--uninstall-extension", extension_id], timeout=60.0)
        return res.returncode == 0
