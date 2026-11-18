"""Read-only native security & posture audits (`wb audit` and `wb doctor` blockers)."""

import sys

from winbearable.audit.models import AuditFinding
from winbearable.audit.models import safe_val as _safe_val
from winbearable.audit.registry_checks import (
    check_autologon_secrets as _check_autologon_secrets,
)
from winbearable.audit.registry_checks import (
    check_autostart_inventory as _check_autostart_inventory,
)
from winbearable.audit.registry_checks import (
    check_bitlocker_protectors as _check_bitlocker_protectors,
)
from winbearable.audit.registry_checks import (
    check_defender_exclusions as _check_defender_exclusions,
)
from winbearable.audit.registry_checks import (
    check_edr_present as _check_edr_present,
)
from winbearable.audit.registry_checks import (
    check_firewall_default_actions as _check_firewall_default_actions,
)
from winbearable.audit.registry_checks import (
    check_legacy_tls as _check_legacy_tls,
)
from winbearable.audit.registry_checks import (
    check_patch_level as _check_patch_level,
)
from winbearable.audit.registry_checks import (
    check_pending_reboot as _check_pending_reboot,
)
from winbearable.audit.registry_checks import (
    check_powershell_clm as _check_powershell_clm,
)
from winbearable.audit.registry_checks import (
    check_tpm_ready as _check_tpm_ready,
)
from winbearable.audit.registry_checks import (
    check_unquoted_service_paths as _check_unquoted_service_paths,
)
from winbearable.audit.registry_checks import (
    check_wdac_present as _check_wdac_present,
)
from winbearable.audit.registry_checks import (
    check_winget_and_store_blocked as _check_winget_and_store_blocked,
)
from winbearable.audit.runner import build_doctor_blockers, run_security_audit
from winbearable.audit.win32_checks import (
    check_guest_account as _check_guest_account,
)
from winbearable.audit.win32_checks import (
    check_hyperv_firewall as _check_hyperv_firewall,
)
from winbearable.audit.win32_checks import (
    check_listening_ports as _check_listening_ports,
)
from winbearable.audit.win32_checks import (
    check_local_admins as _check_local_admins,
)
from winbearable.audit.win32_checks import (
    check_open_shares as _check_open_shares,
)

__all__ = [
    "AuditFinding",
    "_check_autologon_secrets",
    "_check_autostart_inventory",
    "_check_bitlocker_protectors",
    "_check_defender_exclusions",
    "_check_edr_present",
    "_check_firewall_default_actions",
    "_check_guest_account",
    "_check_hyperv_firewall",
    "_check_legacy_tls",
    "_check_listening_ports",
    "_check_local_admins",
    "_check_open_shares",
    "_check_patch_level",
    "_check_pending_reboot",
    "_check_powershell_clm",
    "_check_tpm_ready",
    "_check_unquoted_service_paths",
    "_check_wdac_present",
    "_check_winget_and_store_blocked",
    "_safe_val",
    "build_doctor_blockers",
    "run_security_audit",
    "sys",
]
