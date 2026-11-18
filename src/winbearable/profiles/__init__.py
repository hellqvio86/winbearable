"""TOML and JSON profile loading, inheritance resolution, migration, validation, and generation."""

from winbearable.const import REPO_PROFILES_DIR
from winbearable.profiles.generator import (
    dict_to_toml as _dict_to_toml,
)
from winbearable.profiles.generator import (
    generate_init_profile_json,
    generate_init_profile_toml,
    migrate_profile_file,
)
from winbearable.profiles.loader import (
    MAX_PROFILE_INHERITANCE_DEPTH,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
    resolve_profile_path,
)
from winbearable.profiles.schema_migration import (
    ProfileValidationError,
    migrate_profile_payload,
)

__all__ = [
    "MAX_PROFILE_INHERITANCE_DEPTH",
    "ProfileValidationError",
    "REPO_PROFILES_DIR",
    "_dict_to_toml",
    "generate_init_profile_json",
    "generate_init_profile_toml",
    "get_builtin_profiles_dir",
    "get_default_user_profile_path",
    "load_profile",
    "migrate_profile_file",
    "migrate_profile_payload",
    "resolve_profile_path",
]
