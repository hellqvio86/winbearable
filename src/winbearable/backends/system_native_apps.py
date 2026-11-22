"""OneDrive, Winget, and VS Code extension methods for NativeSystemBackend."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from ..models import OperationOutcome, OperationStatus
from .inventory_cache import InventoryCache
from .system_native_cmd import is_user_writable_binary
from .system_protocol import CommandResult


class NativeAppService:
    """Composed service providing OneDrive, Winget, and VS Code extension operations with explicit dependencies."""

    _is_user_writable_binary = staticmethod(is_user_writable_binary)

    def __init__(
        self,
        *,
        platform_name: str,
        setup_candidates: tuple[str, ...],
        inventory_cache: InventoryCache,
        run_cmd: Callable[..., CommandResult],
        is_process_running: Callable[[str], bool],
        resolve_winget: Callable[[], str],
        resolve_code: Callable[[], str],
        is_admin: Callable[[], bool],
        get_outcome: Callable[[], OperationOutcome | None],
        set_outcome: Callable[[OperationOutcome | None], None],
        is_onedrive_installed: Callable[[], bool] | None = None,
    ) -> None:
        self._platform = platform_name
        self._setup_candidates = setup_candidates
        self._inventory_cache = inventory_cache
        self._run_cmd_fn = run_cmd
        self._is_process_running_fn = is_process_running
        self._resolve_winget_fn = resolve_winget
        self._resolve_code_fn = resolve_code
        self._is_admin_fn = is_admin
        self._get_outcome_fn = get_outcome
        self._set_outcome_fn = set_outcome
        self._is_onedrive_installed_fn = is_onedrive_installed or self.is_onedrive_installed

    @property
    def last_outcome(self) -> OperationOutcome | None:
        return self._get_outcome_fn()

    @last_outcome.setter
    def last_outcome(self, value: OperationOutcome | None) -> None:
        self._set_outcome_fn(value)

    def _run_native_cmd(self, args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        return self._run_cmd_fn(args, input_text=input_text, timeout=timeout)

    def is_process_running(self, process_name: str) -> bool:
        return self._is_process_running_fn(process_name)

    def _resolve_winget_exe(self) -> str:
        return self._resolve_winget_fn()

    def _resolve_code_cmd(self) -> str:
        return self._resolve_code_fn()

    def _check_is_admin(self) -> bool:
        return self._is_admin_fn()

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
                return not self._is_onedrive_installed_fn()
        return False

    @staticmethod
    def _match_winget_id_in_bulk_table(bulk_out: str, package_id: str) -> bool:
        """Match *package_id* strictly in a non-Name column when table separator is present."""
        lines = bulk_out.splitlines()
        has_separator = False
        start_idx = 0
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped and set(stripped) == {"-"}:
                has_separator = True
                start_idx = idx + 1
                break
        prefix = r"^.*?\s{2,}" if has_separator else r"^(?:.*?\s{2,})?"
        id_pat = re.compile(rf"{prefix}{re.escape(package_id)}(?:\s{{2,}}|\s*$)", re.IGNORECASE)
        return any(id_pat.match(line) for line in lines[start_idx:])

    def is_winget_package_installed(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        cache_key = package_id.lower()
        hit, cached_installed = self._inventory_cache.get("winget_pkg", cache_key)
        if hit:
            return bool(cached_installed)
        bulk_hit, bulk_out = self._inventory_cache.get("winget_bulk", "")
        if not bulk_hit:
            bulk_res = self._run_native_cmd(
                [self._resolve_winget_exe(), "list", "--disable-interactivity", "--accept-source-agreements"],
                timeout=60.0,
            )
            if bulk_res.returncode == 0 and bulk_res.stdout.strip():
                bulk_out = bulk_res.stdout
                self._inventory_cache.set("winget_bulk", "", bulk_out)
        if bulk_out is not None:
            installed = self._match_winget_id_in_bulk_table(bulk_out, package_id)
            self._inventory_cache.set("winget_pkg", cache_key, installed)
            return installed
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "list",
                "--id",
                package_id,
                "--exact",
                "--accept-source-agreements",
                "--disable-interactivity",
            ],
            timeout=60.0,
        )
        installed = res.returncode == 0 and bool(
            re.search(rf"(?m)(?:^|\s){re.escape(package_id)}(?:\s|$)", res.stdout, re.IGNORECASE)
        )
        self._inventory_cache.set("winget_pkg", cache_key, installed)
        return installed

    def install_winget_package(
        self,
        package_id: str,
        scope: str = "user",
        vscode_extensions: tuple[str, ...] = (),
    ) -> bool:
        if self._platform != "win32":
            return False
        self._inventory_cache.invalidate("winget_pkg", package_id.lower())
        self._inventory_cache.invalidate("winget_bulk")
        self._inventory_cache.invalidate("vscode_ext")
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
        self._inventory_cache.set("winget_pkg", package_id.lower(), True)
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
        self._inventory_cache.invalidate("vscode_ext")
        ext_res = self._run_native_cmd([code_cmd, "--install-extension", extension_id, "--force"], timeout=120.0)
        return ext_res.returncode == 0

    def uninstall_winget_package(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        self._inventory_cache.invalidate("winget_pkg", package_id.lower())
        self._inventory_cache.invalidate("winget_bulk")
        self._inventory_cache.invalidate("vscode_ext")
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
            self._inventory_cache.set("winget_pkg", package_id.lower(), False)
        return ok

    def is_vscode_extension_installed(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        target = extension_id.lower()
        hit, cached = self._inventory_cache.get("vscode_ext", "")
        if hit and isinstance(cached, set):
            return target in cached
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        res = self._run_native_cmd([code_cmd, "--list-extensions"], timeout=30.0)
        if res.returncode != 0:
            return False
        installed_set = {line.strip().lower() for line in res.stdout.splitlines() if line.strip()}
        self._inventory_cache.set("vscode_ext", "", installed_set)
        return target in installed_set

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        self._inventory_cache.invalidate("vscode_ext")
        res = self._run_native_cmd([code_cmd, "--uninstall-extension", extension_id], timeout=60.0)
        return res.returncode == 0
