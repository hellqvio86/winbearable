# Support & Compatibility Policy

## Tested vs. Supported Windows Builds & Editions

- **Tested build (`DEFAULT_TESTED_BUILDS`):** Windows 11 Build `26300` (`Professional`).
- **Supported build range (`MIN_SUPPORTED_BUILD`):** Windows 11 `26H2+` (`Build >= 26300`) on standard desktop editions (`Home`, `Pro`, `Enterprise`, `Education`; some machine-policy tweaks require `Pro`+). Newer builds `>= 26300` are permitted with standard posture checks; build-floor increases require a compatibility review.

Unsupported targets fail closed with `unsupported_build` or `unsupported_edition`:
- Windows builds `< 26300`
- Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`)
- Windows LTSC (`EnterpriseS`)
- Windows Server editions

## Supported Python Interpreters

- **Python `>= 3.15` only** (targeting final CPython 3.15+ releases, not pre-release `3.15.0b4` betas where `hypothesis` `abi3t` wheels may fail to import). Both standard GIL `3.15` and free-threaded `3.15t` builds are tested in Linux CI; Windows CI currently runs standard `3.15`. Users without Python 3.15 can use the standalone `wb.exe` portable binary from GitHub Releases / Winget.
- All `NativeSystemBackend` and `InMemorySystemBackend` caches and outcomes use thread-local / lock-guarded storage for free-threaded safety.

## API, CLI & Schema Stability Tiers

- **CLI & JSON Schemas (`JSON_SCHEMA_VERSION = "2.0"`):** Public contract covered by stability tests (`wb schema <target>`). Breaking changes require a major schema version bump.
- **Python Import Surface (`winbearable.__all__`):** Supported during Beta with best-effort backwards compatibility; internal submodules (`backends/`, `operations/`, `engine/`, `uac/`, `cli/`) are private implementation details.
- **State & Profile Migrations:** `STATE_SCHEMA_VERSION = 2` and `PROFILE_SCHEMA_VERSION = 2` maintain backwards-compatible migration paths from v1 via `wb migrate {state,config} --apply`.

## Beta Status & Exit Criteria

`winbearable` carries `Development Status :: 4 - Beta` until repeatable disposable-VM acceptance runs ([`docs/vm-acceptance-checklist.md`](vm-acceptance-checklist.md)) are recorded across multiple consecutive releases.

## Release Verification

Release artifacts (PyPI distributions and Winget zips) include GitHub build provenance attestations. When Authenticode signing credentials are configured in CI, signing failures fail the release rather than silently publishing an unsigned binary.
