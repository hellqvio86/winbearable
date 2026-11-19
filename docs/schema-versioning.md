# JSON & State Schema Versioning Policy

`winbearable` tracks three independent schema versions in `src/winbearable/const.py`:

| Constant | Scope | Current Value | Migration Support |
| --- | --- | --- | --- |
| `JSON_SCHEMA_VERSION` | CLI `--json` output envelope (`wb plan`, `wb apply`, `wb status`, `wb doctor`, `wb list`) | `"2.0"` | Consumers inspect `schema_version` |
| `STATE_SCHEMA_VERSION` | Local state journal (`%LOCALAPPDATA%\winbearable\state.json`) | `2` | `wb migrate state` (`migrate_state_payload`) |
| `PROFILE_SCHEMA_VERSION` | TOML / JSON profile files (`*.toml`, `*.json`) | `2` | `wb migrate config` (`migrate_profile_payload`) |

## Bump Rules

- **Additive changes** (adding optional fields to CLI `--json` payloads, `wb doctor` sections such as `refugee_summary`, or optional profile fields) **preserve** the major version or bump the minor component when documented.
- **Breaking changes** (renaming/removing required keys, changing field types, or altering `wb schema <target>` required properties) **must bump** `JSON_SCHEMA_VERSION` (or increment `STATE_SCHEMA_VERSION` / `PROFILE_SCHEMA_VERSION` with a corresponding migration path).
- **Schema inspection**: `wb schema <profile|plan|status|doctor|list>` emits the authoritative JSON Schema matching `JSON_SCHEMA_VERSION`.
