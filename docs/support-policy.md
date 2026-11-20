# Support & Compatibility Policy

## Supported Windows Builds & Editions

`winbearable` targets **Windows 11 26H2+ (Build `>= 26300`)** on standard desktop editions (`Home`, `Pro`, `Enterprise`, `Education`; some machine-policy tweaks require `Pro`+).

Unsupported targets fail closed with `unsupported_build` or `unsupported_edition`:
- Windows builds `< 26300`
- Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`)
- Windows LTSC (`EnterpriseS`)
- Windows Server editions

## Supported Python Interpreters

- **Python `>= 3.15`** (both standard GIL `3.15` and free-threaded `3.15t` builds are tested in CI).
- All `NativeSystemBackend` and `InMemorySystemBackend` caches and outcomes use thread-local / lock-guarded storage for free-threaded safety.

## Schema & State Compatibility

- **State journal (`state.json`):** Backwards-compatible across schema versions (`STATE_SCHEMA_VERSION`), with dry-run-by-default migration via `wb migrate state --apply`.
- **Profiles & configs (`TOML` / `JSON`):** Both formats are first-class (`PROFILE_SCHEMA_VERSION`), with dry-run-by-default migration via `wb migrate config <path> --apply`.
- **CLI JSON contracts:** Machine-readable outputs include `schema_version` (`wb schema <target>`).

## Release Verification

Release artifacts (PyPI distributions and Winget zips) include GitHub build provenance attestations. See the README for `gh attestation verify` commands.
