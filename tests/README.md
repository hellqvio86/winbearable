# Test Suite Map

Tests are grouped by domain so changes can be verified quickly with targeted `pytest` runs before running the full suite.

| Test File | Domain & Coverage |
| --- | --- |
| `tests/test_architecture_invariants.py` | Profile path containment, FileSpec/ICACLS path policy, WSL distro validation, Hyper-V PS quoting, immutable catalogs, schema contract, Winget allowlist, engine phases |
| `tests/test_catalog_lint.py` | Catalog safety invariants, no inline imports, 750-LOC module ceiling, raw `subprocess` boundary, `verify-matrix.md` sync, supply-chain pins |
| `tests/test_catalog_validation.py` | `validate_catalog` schema, conflict, provenance, and build-floor rules |
| `tests/test_cli.py` | CLI subcommands (`doctor`, `status`, `plan`, `apply`, `rollback`, `recover`, `wsl`, `schema`) and exit codes |
| `tests/test_engine_and_tweaks.py` | End-to-end `detect -> apply -> detect -> rollback -> detect` across catalog tweaks |
| `tests/test_engine_posture_and_rollback.py` | Posture audits (Defender, SmartScreen, VBS/HVCI/Credential Guard) and rollback behavior |
| `tests/test_json_and_migration.py` | JSON/TOML profile loading and `wb migrate {config,state}` schema transitions |
| `tests/test_property_invariants.py` | Hypothesis property tests across catalog metadata and config parsers |
| `tests/test_recovery_and_concurrency.py` | Write-ahead journal recovery, `FileSnapshot` atomicity, and `StateStore` locking |
| `tests/test_recovery_and_linux_domain.py` | Linux-side WSL2 audit, sysctl baseline, credential hygiene, and compensation |
| `tests/test_rollback_wsl_uac_and_profiles.py` | WSL `.wslconfig`/`/etc/wsl.conf`, UAC elevation helpers, and profile inheritance |
| `tests/test_tweaks_and_operations.py` | Operation adapters (`registry`, `service`, `file_config`, `winget_package`, `icacls_acl`, etc.) |
| `tests/test_wsl_and_state_domain.py` | WSL INI merging, memory sizing, backup pruning, and state persistence |
| `tests/test_windows_integration.py` | Env-gated real Windows 11 integration suite (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1`) |
