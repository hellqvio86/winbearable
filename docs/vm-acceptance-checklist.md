# Disposable Windows VM Acceptance Checklist

Use this checklist before cutting a minor/major release or after changes to `state.py`, `uac/`, `wsl/`, `win32_acl.py`, or `backends/`. **Never run machine-mutating tests on shared hosted CI runners.**

## 1. Pre-Flight Snapshot
- [ ] Boot a clean Windows 11 (`Build >= 26300`, Pro/Enterprise) VM and take a hypervisor snapshot (`pre-wb-test`).
- [ ] Record exact OS build, edition, Python version (`wb --version`), and WSL version (`wsl --version`).

## 2. Standard User & Canary Apply/Rollback
- [ ] Run `wb doctor --json` and verify `state_acl_ok: true` and `windows_build_supported: true`.
- [ ] Run `wb plan --profile user-only` and verify no unexpected machine-scope changes.
- [ ] Run `wb apply --profile user-only --only explorer.show_file_extensions,explorer.show_hidden_files` and verify convergence (`wb status --profile user-only`).
- [ ] Run `wb rollback --apply` and repeated `wb rollback --apply` (idempotency check).

## 3. Admin, UAC & Crash Recovery
- [ ] Test `--elevate` without `--allow-user-writable-elevation-target` from a user-writable `.venv` (must fail closed).
- [ ] Test `--elevate --allow-user-writable-elevation-target` and verify UAC cancellation (`ERROR_CANCELLED`) leaves state clean.
- [ ] Test mid-run recovery via `wb recover` (dry-run) -> `wb recover --apply`.

## 4. WSL & Managed-Device Checks
- [ ] Verify `wb wsl plan --mode convenient` and `wb wsl apply --mode convenient --apply` on a disposable distro (confirm `docker-desktop` is excluded).
- [ ] Restore VM snapshot `pre-wb-test` after verification.
