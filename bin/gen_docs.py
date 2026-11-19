"""Generate docs/tweaks-reference.md from the authoritative TWEAK_CATALOG."""

from pathlib import Path

from winbearable.profiles import get_builtin_profiles_dir, load_profile
from winbearable.tweaks import get_all_tweaks


def render_tweaks_reference_markdown() -> str:
    """Render docs/tweaks-reference.md deterministically from TWEAK_CATALOG and built-in profiles."""
    profiles_dir = get_builtin_profiles_dir()
    profile_tweaks: dict[str, set[str]] = {}
    if profiles_dir.is_dir():
        for p_file in sorted(profiles_dir.glob("*.toml")):
            loaded = load_profile(str(p_file))
            profile_tweaks[loaded.name] = {tid for tid, en in loaded.tweaks.items() if en}

    lines = [
        "# Per-Tweak Catalog Reference (`winbearable`)",
        "",
        (
            "Every tweak in `winbearable` targets the maintainer's current "
            "**Windows 11 desktop installation (`26H2+`, Build `>= 26300` — NO Windows IoT or LTSC)**, "
            "operates in **100% native Python** (`winreg`, `sc.exe`, `schtasks.exe`, `dism.exe`, "
            "`winget.exe`, `auditpol.exe`, `wevtutil.exe`, `netsh.exe`, `taskkill.exe`), records pre-apply "
            "state in `%LOCALAPPDATA%\\winbearable\\state.json`, and is reversible via `wb rollback --apply` "
            "(unless explicitly marked `irreversible`)."
        ),
        "",
        "| Tweak ID | Category | Admin? | Risk | CIS ID | Profiles | Summary |",
        "| :--- | :--- | :---: | :---: | :---: | :--- | :--- |",
    ]
    for tweak in get_all_tweaks():
        admin_str = "Yes" if tweak.requires_admin else "No"
        cis_str = f"`{tweak.cis_id}`" if tweak.cis_id else "—"
        members = [f"`{pname}`" for pname, tids in profile_tweaks.items() if tweak.tweak_id in tids]
        prof_str = ", ".join(members) if members else "*opt-in*"
        summary = tweak.title.replace("|", "\\|")
        lines.append(
            f"| `{tweak.tweak_id}` | `{tweak.category}` | {admin_str} | `{tweak.risk}` "
            f"| {cis_str} | {prof_str} | {summary} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    out_path = repo_root / "docs" / "tweaks-reference.md"
    out_path.write_text(render_tweaks_reference_markdown(), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
