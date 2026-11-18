"""Profile path resolution, validation, inheritance resolution, and loading."""

from __future__ import annotations

import os
import sys
import warnings
from pathlib import Path
from typing import Any

from ..const import (
    BUNDLED_PROFILES_DIR,
    DEFAULT_WSL_NETWORKING_MODE,
    ENV_CONFIG_PATH,
    ENV_PROFILE_DIR,
    REPO_PROFILES_DIR,
    WSL_MODES,
)
from ..models import ProfileSpec, WslConfigSpec
from ..packages import PACKAGE_CATALOG, PACKAGE_PRESETS
from ..tweaks import TWEAK_CATALOG, TWEAK_ID_ALIASES, resolve_tweak_id
from .schema_migration import (
    ProfileValidationError,
    find_key_line,
    migrate_profile_payload,
    parse_profile_content,
)


def get_builtin_profiles_dir() -> Path:
    """Resolve the directory containing built-in TOML profiles."""
    override = os.environ.get(ENV_PROFILE_DIR)
    if override:
        return Path(override)
    pkg_mod = sys.modules.get("winbearable.profiles")
    repo_dir = getattr(pkg_mod, "REPO_PROFILES_DIR", REPO_PROFILES_DIR) if pkg_mod is not None else REPO_PROFILES_DIR
    if repo_dir.is_dir():
        return repo_dir
    return BUNDLED_PROFILES_DIR


def resolve_profile_path(name_or_path: str) -> Path:
    """Resolve a profile name ('user-only', 'owner', 'paranoid') or TOML/JSON file path."""
    candidate_path = Path(name_or_path)
    if candidate_path.is_file():
        return candidate_path

    profiles_dir = get_builtin_profiles_dir()
    if name_or_path.endswith(".json"):
        stem = name_or_path[:-5]
        suffixes = (".json", ".toml")
    elif name_or_path.endswith(".toml"):
        stem = name_or_path[:-5]
        suffixes = (".toml", ".json")
    else:
        stem = name_or_path
        suffixes = (".toml", ".json")

    for ext in suffixes:
        builtin_file = profiles_dir / f"{stem}{ext}"
        if builtin_file.is_file():
            return builtin_file

    raise ProfileValidationError(f"Profile '{name_or_path}' not found at {candidate_path} or in {profiles_dir}.")


def _require_bool(raw: dict[str, Any], key: str, default: bool) -> bool:
    if key not in raw:
        return default
    val = raw[key]
    if not isinstance(val, bool):
        raise ProfileValidationError(f"wsl.{key} must be a boolean, got {type(val).__name__}.")
    return val


def _require_bounded_int(raw: dict[str, Any], key: str, default: int | None, min_val: int, max_val: int) -> int | None:
    if key not in raw:
        return default
    val = raw[key]
    if val is None:
        return None
    if isinstance(val, bool) or not isinstance(val, int):
        raise ProfileValidationError(f"wsl.{key} must be an integer, got {type(val).__name__}.")
    if val < min_val or val > max_val:
        raise ProfileValidationError(f"wsl.{key} must be between {min_val} and {max_val}, got {val}.")
    return val


def _parse_wsl_section(
    raw_wsl: dict[str, Any],
    base_wsl: WslConfigSpec | None = None,
    content: str = "",
) -> WslConfigSpec:
    allowed_wsl_keys = {
        "enabled",
        "mode",
        "networking_mode",
        "dns_tunneling",
        "firewall",
        "auto_proxy",
        "systemd",
        "memory_gb",
        "processors",
        "vm_idle_timeout",
        "gui_applications",
        "nested_virtualization",
        "debug_console",
        "kernel_command_line",
        "default_vhd_size",
        "host_address_loopback",
        "ignored_ports",
        "best_effort_dns_parsing",
        "default_user",
        "hostname",
        "generate_hosts",
        "generate_resolv_conf",
        "automount_root",
        "cross_distro",
        "credentials",
        "distro",
    }
    unknown_wsl = set(raw_wsl.keys()) - allowed_wsl_keys
    if unknown_wsl:
        first = sorted(unknown_wsl)[0]
        ln = find_key_line(content, first)
        ln_hint = f" (line {ln})" if ln else ""
        raise ProfileValidationError(f"Unknown [wsl] keys{ln_hint}: {', '.join(sorted(unknown_wsl))}")

    defaults = base_wsl or WslConfigSpec()
    raw_mode = raw_wsl.get("mode", defaults.mode)
    if not isinstance(raw_mode, str) or raw_mode not in WSL_MODES:
        raise ProfileValidationError(f"Invalid wsl.mode '{raw_mode}'. Must be one of: {', '.join(WSL_MODES)}")

    raw_net = raw_wsl.get("networking_mode", defaults.networking_mode or DEFAULT_WSL_NETWORKING_MODE)
    allowed_net_modes = {"mirrored", "nat", "none", "bridged"}
    if not isinstance(raw_net, str) or raw_net not in allowed_net_modes:
        raise ProfileValidationError(
            f"Invalid wsl.networking_mode '{raw_net}'. Must be one of: {', '.join(sorted(allowed_net_modes))}"
        )

    memory_gb = _require_bounded_int(raw_wsl, "memory_gb", defaults.memory_gb, 1, 4096)
    processors = _require_bounded_int(raw_wsl, "processors", defaults.processors, 1, 1024)
    vm_idle_timeout = _require_bounded_int(raw_wsl, "vm_idle_timeout", defaults.vm_idle_timeout, 0, 86400000)

    def _opt_bool(k: str, default: bool | None) -> bool | None:
        if k not in raw_wsl:
            return default
        v = raw_wsl[k]
        if v is None:
            return None
        if not isinstance(v, bool):
            raise ProfileValidationError(f"wsl.{k} must be a boolean, got {type(v).__name__}.")
        return v

    def _opt_str(k: str, default: str | None) -> str | None:
        if k not in raw_wsl:
            return default
        v = raw_wsl[k]
        if v is None:
            return None
        if not isinstance(v, str):
            raise ProfileValidationError(f"wsl.{k} must be a string, got {type(v).__name__}.")
        return v

    default_user = _opt_str("default_user", defaults.default_user)
    if default_user is not None and default_user.strip().lower() == "root":
        raise ProfileValidationError("wsl.default_user cannot be 'root'.")

    raw_ports = raw_wsl.get("ignored_ports", defaults.ignored_ports)
    ignored_ports: tuple[int, ...] | None = None
    if raw_ports is not None:
        if not isinstance(raw_ports, (list, tuple)) or any(
            isinstance(p, bool) or not isinstance(p, int) or p < 1 or p > 65535 for p in raw_ports
        ):
            raise ProfileValidationError("wsl.ignored_ports must be a list of valid TCP/UDP port integers (1..65535).")
        ignored_ports = tuple(int(p) for p in raw_ports)

    raw_creds = raw_wsl.get("credentials", defaults.credentials)
    if not isinstance(raw_creds, str) or raw_creds not in {"isolated", "bridged"}:
        raise ProfileValidationError(f"Invalid wsl.credentials '{raw_creds}'. Must be 'isolated' or 'bridged'.")

    return WslConfigSpec(
        enabled=_require_bool(raw_wsl, "enabled", defaults.enabled),
        mode=raw_mode,
        networking_mode=raw_net,
        dns_tunneling=_require_bool(raw_wsl, "dns_tunneling", defaults.dns_tunneling),
        firewall=_require_bool(raw_wsl, "firewall", defaults.firewall),
        auto_proxy=_require_bool(raw_wsl, "auto_proxy", defaults.auto_proxy),
        systemd=_require_bool(raw_wsl, "systemd", defaults.systemd),
        memory_gb=memory_gb,
        processors=processors,
        vm_idle_timeout=vm_idle_timeout,
        gui_applications=_opt_bool("gui_applications", defaults.gui_applications),
        nested_virtualization=_opt_bool("nested_virtualization", defaults.nested_virtualization),
        debug_console=_opt_bool("debug_console", defaults.debug_console),
        kernel_command_line=_opt_str("kernel_command_line", defaults.kernel_command_line),
        default_vhd_size=_opt_str("default_vhd_size", defaults.default_vhd_size),
        host_address_loopback=_opt_bool("host_address_loopback", defaults.host_address_loopback),
        ignored_ports=ignored_ports,
        best_effort_dns_parsing=_opt_bool("best_effort_dns_parsing", defaults.best_effort_dns_parsing),
        default_user=default_user,
        hostname=_opt_str("hostname", defaults.hostname),
        generate_hosts=_opt_bool("generate_hosts", defaults.generate_hosts),
        generate_resolv_conf=_opt_bool("generate_resolv_conf", defaults.generate_resolv_conf),
        automount_root=_opt_str("automount_root", defaults.automount_root),
        cross_distro=_opt_bool("cross_distro", defaults.cross_distro),
        credentials=raw_creds,
    )


def validate_raw_profile(raw_data: dict[str, Any], source_label: str, content: str = "") -> None:
    allowed_top_keys = {
        "schema_version",
        "name",
        "description",
        "extends",
        "include",
        "wsl",
        "tweaks",
        "packages",
        "params",
    }
    unknown_top = set(raw_data.keys()) - allowed_top_keys
    if unknown_top:
        first = sorted(unknown_top)[0]
        ln = find_key_line(content, first)
        ln_hint = f" (line {ln})" if ln else ""
        raise ProfileValidationError(
            f"Profile '{source_label}' contains unknown top-level keys{ln_hint}: {', '.join(sorted(unknown_top))}"
        )

    if "name" not in raw_data or not isinstance(raw_data["name"], str):
        raise ProfileValidationError(f"Profile '{source_label}' must define a string 'name'.")
    if "description" in raw_data and not isinstance(raw_data["description"], str):
        raise ProfileValidationError(f"Profile '{source_label}' 'description' must be a string.")
    if "extends" in raw_data and raw_data["extends"] is not None and not isinstance(raw_data["extends"], str):
        raise ProfileValidationError(f"Profile '{source_label}' 'extends' must be a string.")
    if "include" in raw_data and (
        not isinstance(raw_data["include"], list) or any(not isinstance(x, str) for x in raw_data["include"])
    ):
        raise ProfileValidationError(f"Profile '{source_label}' 'include' must be a list of strings.")

    raw_wsl_chk = raw_data.get("wsl", {})
    if not isinstance(raw_wsl_chk, dict):
        raise ProfileValidationError(f"Profile '{source_label}' [wsl] must be a table.")
    _parse_wsl_section(raw_wsl_chk, content=content)

    raw_tweaks = raw_data.get("tweaks", {})
    if not isinstance(raw_tweaks, dict):
        raise ProfileValidationError(f"Profile '{source_label}' [tweaks] section must be a table.")

    for tweak_id, enabled in raw_tweaks.items():
        canonical_id = resolve_tweak_id(tweak_id)
        if tweak_id in TWEAK_ID_ALIASES:
            warnings.warn(
                f"Profile '{source_label}' uses deprecated tweak ID '{tweak_id}'; use '{canonical_id}' instead.",
                DeprecationWarning,
                stacklevel=3,
            )
        if canonical_id not in TWEAK_CATALOG:
            ln = find_key_line(content, tweak_id)
            ln_hint = f" (line {ln})" if ln else ""
            raise ProfileValidationError(f"Profile '{source_label}' references unknown tweak ID '{tweak_id}'{ln_hint}.")
        if not isinstance(enabled, bool):
            raise ProfileValidationError(
                f"Profile '{source_label}' tweak '{tweak_id}' value must be a boolean, got {type(enabled).__name__}."
            )

    raw_packages = raw_data.get("packages", {})
    if not isinstance(raw_packages, dict):
        raise ProfileValidationError(f"Profile '{source_label}' [packages] section must be a table.")
    allowed_pkg_keys = {"install", "presets", "remove"}
    unknown_pkg = set(raw_packages.keys()) - allowed_pkg_keys
    if unknown_pkg:
        first = sorted(unknown_pkg)[0]
        ln = find_key_line(content, first)
        ln_hint = f" (line {ln})" if ln else ""
        raise ProfileValidationError(
            f"Profile '{source_label}' unknown [packages] keys{ln_hint}: {', '.join(sorted(unknown_pkg))}"
        )
    for pkg_list_key in ("install", "presets", "remove"):
        if pkg_list_key in raw_packages and not isinstance(raw_packages[pkg_list_key], list):
            raise ProfileValidationError(f"Profile '{source_label}' [packages.{pkg_list_key}] must be a list.")
    for pkg_name in raw_packages.get("install", []):
        if pkg_name not in PACKAGE_CATALOG:
            raise ProfileValidationError(f"Profile '{source_label}' references unknown catalog package '{pkg_name}'.")
    for preset_name in raw_packages.get("presets", []):
        if preset_name not in PACKAGE_PRESETS:
            raise ProfileValidationError(f"Profile '{source_label}' references unknown package preset '{preset_name}'.")
    for rem_name in raw_packages.get("remove", []):
        if not isinstance(rem_name, str) or not rem_name.strip():
            raise ProfileValidationError(
                f"Profile '{source_label}' [packages.remove] entries must be non-empty strings."
            )

    raw_params = raw_data.get("params", {})
    if not isinstance(raw_params, dict):
        raise ProfileValidationError(f"Profile '{source_label}' [params] section must be a table.")
    for tid, param_map in raw_params.items():
        if resolve_tweak_id(tid) not in TWEAK_CATALOG:
            raise ProfileValidationError(f"Profile '{source_label}' [params] references unknown tweak ID '{tid}'.")
        if not isinstance(param_map, dict):
            raise ProfileValidationError(f"Profile '{source_label}' [params.\"{tid}\"] must be a table.")


MAX_PROFILE_INHERITANCE_DEPTH = 8


def _resolve_sibling_profile(parent_dir: Path, ref: str) -> str:
    """Resolve a sibling .toml or .json profile relative to parent_dir, falling back to ref."""
    if ref.endswith((".toml", ".json")):
        candidate = parent_dir / ref
        return str(candidate) if candidate.is_file() else ref
    for ext in (".toml", ".json"):
        candidate = parent_dir / f"{ref}{ext}"
        if candidate.is_file():
            return str(candidate)
    return ref


def load_profile(
    name_or_path: str,
    _visited: set[Path] | None = None,
    _chain: tuple[tuple[str, str], ...] = (),
    _edge: str = "root",
) -> ProfileSpec:
    """Load a TOML or JSON profile, migrate legacy fields, and resolve 'extends'/'include'."""
    profile_path = resolve_profile_path(name_or_path).resolve()
    current_chain = (*_chain, (_edge, str(profile_path)))
    if len(current_chain) > MAX_PROFILE_INHERITANCE_DEPTH:
        chain_str = " -> ".join(f"{edge}:{p}" for edge, p in current_chain)
        raise ProfileValidationError(
            f"Profile inheritance depth exceeded maximum ({MAX_PROFILE_INHERITANCE_DEPTH}): {chain_str}"
        )
    visited = _visited or set()
    if profile_path in visited:
        chain_str = " -> ".join(f"{edge}:{p}" for edge, p in current_chain)
        raise ProfileValidationError(f"Circular profile inheritance detected involving {profile_path}: {chain_str}")
    path_visited = visited | {profile_path}

    content = profile_path.read_text(encoding="utf-8")
    parsed_data, _ = parse_profile_content(content, profile_path)
    raw_data, _, _ = migrate_profile_payload(parsed_data, source_label=str(profile_path))

    validate_raw_profile(raw_data, str(profile_path), content=content)

    extends_ref = raw_data.get("extends")
    base_profile: ProfileSpec | None = None
    if extends_ref is not None:
        if not isinstance(extends_ref, str):
            raise ProfileValidationError(f"Profile {profile_path} 'extends' must be a string.")
        target_ref = _resolve_sibling_profile(profile_path.parent, extends_ref)
        base_profile = load_profile(target_ref, _visited=path_visited, _chain=current_chain, _edge="extends")

    merged_tweaks: dict[str, bool] = {}
    if base_profile is not None:
        merged_tweaks.update(base_profile.tweaks)

    pkg_list: list[str] = list(base_profile.packages) if base_profile else []
    pkg_remove: list[str] = list(base_profile.packages_remove) if base_profile else []
    merged_params: dict[str, dict[str, Any]] = {
        k: dict(v) for k, v in (base_profile.params.items() if base_profile else ())
    }
    wsl_distros: dict[str, dict[str, Any]] = {
        k: dict(v) for k, v in (base_profile.wsl_distros.items() if base_profile else ())
    }

    includes_raw = raw_data.get("include", [])
    resolved_includes: list[str] = list(base_profile.includes) if base_profile else []
    for inc_ref in includes_raw:
        if not isinstance(inc_ref, str):
            raise ProfileValidationError(f"Profile {profile_path} 'include' entries must be strings.")
        inc_target = _resolve_sibling_profile(profile_path.parent, inc_ref)
        inc_profile = load_profile(inc_target, _visited=path_visited, _chain=current_chain, _edge="include")
        merged_tweaks.update(inc_profile.tweaks)
        for p_name in inc_profile.packages:
            if p_name not in pkg_list:
                pkg_list.append(p_name)
        for r_name in inc_profile.packages_remove:
            if r_name not in pkg_remove:
                pkg_remove.append(r_name)
        for tid, p_map in inc_profile.params.items():
            merged_params.setdefault(tid, {}).update(p_map)
        for d_name, d_cfg in inc_profile.wsl_distros.items():
            wsl_distros.setdefault(d_name, {}).update(d_cfg)
        for tr_inc in inc_profile.includes:
            if tr_inc not in resolved_includes:
                resolved_includes.append(tr_inc)
        resolved_includes.append(inc_ref)

    for tweak_id, enabled in raw_data.get("tweaks", {}).items():
        merged_tweaks[resolve_tweak_id(str(tweak_id))] = bool(enabled)

    raw_wsl = raw_data.get("wsl", {})
    if not isinstance(raw_wsl, dict):
        raise ProfileValidationError(f"Profile {profile_path} [wsl] must be a table.")
    wsl_spec = _parse_wsl_section(raw_wsl, base_profile.wsl if base_profile else None, content=content)

    raw_pkgs = raw_data.get("packages", {})
    for preset in raw_pkgs.get("presets", []):
        for p_name in PACKAGE_PRESETS[preset]:
            if p_name not in pkg_list:
                pkg_list.append(p_name)
    for p_name in raw_pkgs.get("install", []):
        if p_name not in pkg_list:
            pkg_list.append(p_name)
    for r_name in raw_pkgs.get("remove", []):
        if r_name not in pkg_remove:
            pkg_remove.append(r_name)

    for tid, p_map in raw_data.get("params", {}).items():
        merged_params.setdefault(tid, {}).update(p_map)

    raw_distros = raw_wsl.get("distro", {})
    if isinstance(raw_distros, dict):
        for d_name, d_cfg in raw_distros.items():
            if isinstance(d_cfg, dict):
                wsl_distros.setdefault(str(d_name), {}).update(d_cfg)

    return ProfileSpec(
        name=str(raw_data["name"]),
        description=str(raw_data.get("description", "")),
        extends=str(extends_ref) if extends_ref else None,
        wsl=wsl_spec,
        tweaks=merged_tweaks,
        packages=tuple(pkg_list),
        packages_remove=tuple(pkg_remove),
        params=merged_params,
        wsl_distros=wsl_distros,
        includes=tuple(resolved_includes),
    )


def get_default_user_profile_path() -> Path:
    """Return user override profile path (~/.config/winbearable/profile.toml or profile.json)."""
    override = os.environ.get(ENV_CONFIG_PATH)
    if override:
        return Path(override)
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base_dir = (Path(xdg_config) / "winbearable") if xdg_config else (Path.home() / ".config" / "winbearable")
    toml_path = base_dir / "profile.toml"
    json_path = base_dir / "profile.json"
    if json_path.is_file() and not toml_path.is_file():
        return json_path
    return toml_path
