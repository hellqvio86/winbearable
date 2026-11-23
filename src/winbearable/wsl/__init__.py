"""Non-destructive .wslconfig and /etc/wsl.conf management and 75% RAM sizing."""

from winbearable.wsl.audit import (
    audit_credential_hygiene as _audit_credential_hygiene,
)
from winbearable.wsl.audit import (
    audit_linux_side,
    audit_wsl,
    deep_audit_wsl_distro,
    detect_default_wsl_distro,
)
from winbearable.wsl.audit import (
    parse_bool_flag as _parse_bool_flag,
)
from winbearable.wsl.audit import (
    read_git_system_credential_helpers as _read_git_system_credential_helpers,
)
from winbearable.wsl.config import (
    PreparedWslDistroPlan,
    PreparedWslPlan,
    WslDistroConfProbe,
    apply_distro_wsl_conf,
    apply_wslconfig_target,
    get_wsl_distro_guid,
    lint_wsl_conf_lf,
    plan_or_apply_wsl,
    prepare_wsl_plan,
    probe_distro_wsl_conf,
)
from winbearable.wsl.consts import (
    INTERNAL_WSL_DISTROS,
    filter_manageable_wsl_distros,
    is_internal_wsl_distro,
)
from winbearable.wsl.ini import (
    KEY_VALUE_RE,
    SECTION_HEADER_RE,
    WslOperationError,
    build_distro_wsl_conf_sections,
    build_wslconfig_sections,
    calculate_wsl_memory_gib,
    detect_wsl_policies,
    format_host_memory_gib,
    get_default_wslconfig_path,
    is_wsl_version_outdated,
    merge_ini_preserving_comments,
)
from winbearable.wsl.ini import atomic_write_text as _atomic_write_text
from winbearable.wsl.ini import create_backup_file as _create_backup_file
from winbearable.wsl.ini import parse_ini_sections as _parse_ini_sections
from winbearable.wsl.ini import parse_version_tuple as _parse_version_tuple
from winbearable.wsl.lifecycle import (
    WSL_LINUX_SYSCTL_CONF,
    apply_wsl_linux_baseline,
    detect_wsl_package_manager,
    export_wsl_distro,
    import_wsl_distro,
    install_wsl_distro,
    set_default_wsl_distro,
    set_wsl_distro_sparse,
    update_wsl,
)

__all__ = [
    "INTERNAL_WSL_DISTROS",
    "KEY_VALUE_RE",
    "SECTION_HEADER_RE",
    "WSL_LINUX_SYSCTL_CONF",
    "PreparedWslDistroPlan",
    "PreparedWslPlan",
    "WslDistroConfProbe",
    "WslOperationError",
    "_atomic_write_text",
    "_audit_credential_hygiene",
    "_create_backup_file",
    "_parse_bool_flag",
    "_parse_ini_sections",
    "_parse_version_tuple",
    "_read_git_system_credential_helpers",
    "apply_distro_wsl_conf",
    "apply_wsl_linux_baseline",
    "apply_wslconfig_target",
    "audit_linux_side",
    "audit_wsl",
    "build_distro_wsl_conf_sections",
    "build_wslconfig_sections",
    "calculate_wsl_memory_gib",
    "deep_audit_wsl_distro",
    "detect_default_wsl_distro",
    "detect_wsl_package_manager",
    "detect_wsl_policies",
    "export_wsl_distro",
    "filter_manageable_wsl_distros",
    "format_host_memory_gib",
    "get_default_wslconfig_path",
    "get_wsl_distro_guid",
    "import_wsl_distro",
    "install_wsl_distro",
    "is_internal_wsl_distro",
    "is_wsl_version_outdated",
    "lint_wsl_conf_lf",
    "merge_ini_preserving_comments",
    "plan_or_apply_wsl",
    "prepare_wsl_plan",
    "probe_distro_wsl_conf",
    "set_default_wsl_distro",
    "set_wsl_distro_sparse",
    "update_wsl",
]
