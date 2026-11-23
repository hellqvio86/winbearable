"""Pre-apply rollback snapshots and transactional run records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from winbearable.models.enums import (
    RegistryValueData,
    RegistryView,
    decode_registry_data,
    encode_registry_data,
)

from .journal import (
    VALID_JOURNAL_OPERATION_TYPES as VALID_JOURNAL_OPERATION_TYPES,
)
from .journal import (
    VALID_JOURNAL_OUTCOMES as VALID_JOURNAL_OUTCOMES,
)
from .journal import (
    FailureOutcomeDict as FailureOutcomeDict,
)
from .journal import (
    OperationJournalEntry as OperationJournalEntry,
)


@dataclass(frozen=True)
class RegistryValueSnapshot:
    """Recorded pre-apply state of a single registry value for exact rollback."""

    hive: str
    key_path: str
    value_name: str
    key_existed: bool
    value_existed: bool
    previous_data: RegistryValueData
    previous_type: str | None
    view: RegistryView = RegistryView.DEFAULT
    post_existed: bool | None = None
    post_data: RegistryValueData = None
    post_type: str | None = None

    @property
    def full_key_path(self) -> str:
        """Return HKCU\\... or HKLM\\... key path."""
        return f"{self.hive}\\{self.key_path}"

    @property
    def display_value_name(self) -> str:
        """Return value name or '(Default)'."""
        return self.value_name if self.value_name else "(Default)"

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to a JSON-compatible dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "key_existed": self.key_existed,
            "value_existed": self.value_existed,
            "previous_data": encode_registry_data(self.previous_data),
            "previous_type": self.previous_type,
            "view": str(self.view),
            "post_existed": self.post_existed,
            "post_data": encode_registry_data(self.post_data),
            "post_type": self.post_type,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RegistryValueSnapshot:
        """Deserialize snapshot from dictionary."""
        raw_view = payload.get("view", RegistryView.DEFAULT)
        try:
            view = RegistryView(str(raw_view))
        except ValueError:
            view = RegistryView.DEFAULT
        raw_post_existed = payload.get("post_existed")
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            value_name=str(payload["value_name"]),
            key_existed=bool(payload["key_existed"]),
            value_existed=bool(payload["value_existed"]),
            previous_data=decode_registry_data(payload.get("previous_data")),
            previous_type=payload.get("previous_type"),
            view=view,
            post_existed=bool(raw_post_existed) if raw_post_existed is not None else None,
            post_data=decode_registry_data(payload.get("post_data")),
            post_type=payload.get("post_type"),
        )


@dataclass(frozen=True)
class ServiceSnapshot:
    """Recorded pre-apply state of a Windows service start type."""

    service_name: str
    previous_start_type: int | None
    post_start_type: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize service snapshot to a dictionary."""
        d: dict[str, Any] = {
            "service_name": self.service_name,
            "previous_start_type": self.previous_start_type,
        }
        if self.post_start_type is not None:
            d["post_start_type"] = self.post_start_type
        return d

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ServiceSnapshot:
        """Deserialize service snapshot from dictionary."""
        prev = payload.get("previous_start_type")
        post = payload.get("post_start_type")
        return cls(
            service_name=str(payload["service_name"]),
            previous_start_type=int(prev) if prev is not None else None,
            post_start_type=int(post) if post is not None else None,
        )


@dataclass(frozen=True)
class ScheduledTaskSnapshot:
    """Recorded pre-apply state of a Windows scheduled task."""

    task_path: str
    previous_enabled: bool | None
    post_enabled: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize scheduled task snapshot to a dictionary."""
        d: dict[str, Any] = {
            "task_path": self.task_path,
            "previous_enabled": self.previous_enabled,
        }
        if self.post_enabled is not None:
            d["post_enabled"] = self.post_enabled
        return d

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ScheduledTaskSnapshot:
        """Deserialize scheduled task snapshot from dictionary."""
        prev = payload.get("previous_enabled")
        post = payload.get("post_enabled")
        return cls(
            task_path=str(payload["task_path"]),
            previous_enabled=bool(prev) if prev is not None else None,
            post_enabled=bool(post) if post is not None else None,
        )


@dataclass(frozen=True)
class OptionalFeatureSnapshot:
    """Recorded pre-apply state of a Windows optional feature."""

    feature_name: str
    previous_enabled: bool | None
    post_enabled: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize optional feature snapshot to a dictionary."""
        d: dict[str, Any] = {
            "feature_name": self.feature_name,
            "previous_enabled": self.previous_enabled,
        }
        if self.post_enabled is not None:
            d["post_enabled"] = self.post_enabled
        return d

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OptionalFeatureSnapshot:
        """Deserialize optional feature snapshot from dictionary."""
        prev = payload.get("previous_enabled")
        post = payload.get("post_enabled")
        return cls(
            feature_name=str(payload["feature_name"]),
            previous_enabled=bool(prev) if prev is not None else None,
            post_enabled=bool(post) if post is not None else None,
        )


@dataclass(frozen=True)
class RegistryKeySnapshot:
    """Recorded pre-apply subtree state of a deleted registry key for exact rollback."""

    hive: str
    key_path: str
    existed: bool
    values: tuple[RegistryValueSnapshot, ...] = ()
    subkeys: tuple[str, ...] = ()
    view: RegistryView = RegistryView.DEFAULT
    post_existed: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize key snapshot to a JSON-compatible dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "existed": self.existed,
            "values": [v.to_dict() for v in self.values],
            "subkeys": list(self.subkeys),
            "view": str(self.view),
            "post_existed": self.post_existed,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RegistryKeySnapshot:
        """Deserialize key snapshot from dictionary."""
        raw_view = payload.get("view", RegistryView.DEFAULT)
        try:
            view = RegistryView(str(raw_view))
        except ValueError:
            view = RegistryView.DEFAULT
        raw_post = payload.get("post_existed")
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            existed=bool(payload["existed"]),
            values=tuple(RegistryValueSnapshot.from_dict(v) for v in payload.get("values", [])),
            subkeys=tuple(str(s) for s in payload.get("subkeys", [])),
            view=view,
            post_existed=bool(raw_post) if raw_post is not None else None,
        )


@dataclass(frozen=True)
class AuditpolSnapshot:
    """Recorded pre-apply state of an auditpol subcategory."""

    subcategory_guid: str
    previous_setting: str | None
    backup_csv_path: str | None = None
    post_setting: str | None = None
    backup_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subcategory_guid": self.subcategory_guid,
            "previous_setting": self.previous_setting,
            "backup_csv_path": self.backup_csv_path,
            "post_setting": self.post_setting,
            "backup_sha256": self.backup_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AuditpolSnapshot:
        prev = payload.get("previous_setting")
        bak = payload.get("backup_csv_path")
        post = payload.get("post_setting")
        sha = payload.get("backup_sha256")
        return cls(
            subcategory_guid=str(payload["subcategory_guid"]),
            previous_setting=str(prev) if prev is not None else None,
            backup_csv_path=str(bak) if bak is not None else None,
            post_setting=str(post) if post is not None else None,
            backup_sha256=str(sha) if sha is not None else None,
        )


@dataclass(frozen=True)
class WevtutilSnapshot:
    """Recorded pre-apply state of a Windows Event Log channel."""

    channel: str
    previous_enabled: bool | None
    previous_max_size_bytes: int | None
    post_enabled: bool | None = None
    post_max_size_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "previous_enabled": self.previous_enabled,
            "previous_max_size_bytes": self.previous_max_size_bytes,
            "post_enabled": self.post_enabled,
            "post_max_size_bytes": self.post_max_size_bytes,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> WevtutilSnapshot:
        prev_en = payload.get("previous_enabled")
        prev_sz = payload.get("previous_max_size_bytes")
        post_en = payload.get("post_enabled")
        post_sz = payload.get("post_max_size_bytes")
        return cls(
            channel=str(payload["channel"]),
            previous_enabled=bool(prev_en) if prev_en is not None else None,
            previous_max_size_bytes=int(prev_sz) if prev_sz is not None else None,
            post_enabled=bool(post_en) if post_en is not None else None,
            post_max_size_bytes=int(post_sz) if post_sz is not None else None,
        )


@dataclass(frozen=True)
class FirewallGroupSnapshot:
    """Recorded pre-apply state of a Windows Firewall rule group."""

    group_resource_id: str
    previous_enabled: bool | None
    export_wfw_path: str | None = None
    post_enabled: bool | None = None
    backup_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_resource_id": self.group_resource_id,
            "previous_enabled": self.previous_enabled,
            "export_wfw_path": self.export_wfw_path,
            "post_enabled": self.post_enabled,
            "backup_sha256": self.backup_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FirewallGroupSnapshot:
        prev = payload.get("previous_enabled")
        wfw = payload.get("export_wfw_path")
        post = payload.get("post_enabled")
        sha = payload.get("backup_sha256")
        return cls(
            group_resource_id=str(payload["group_resource_id"]),
            previous_enabled=bool(prev) if prev is not None else None,
            export_wfw_path=str(wfw) if wfw is not None else None,
            post_enabled=bool(post) if post is not None else None,
            backup_sha256=str(sha) if sha is not None else None,
        )


@dataclass(frozen=True)
class FsutilSnapshot:
    """Recorded pre-apply state of per-directory NTFS case sensitivity."""

    directory: str
    previous_enabled: bool | None
    post_enabled: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "previous_enabled": self.previous_enabled,
            "post_enabled": self.post_enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FsutilSnapshot:
        prev = payload.get("previous_enabled")
        post = payload.get("post_enabled")
        return cls(
            directory=str(payload["directory"]),
            previous_enabled=bool(prev) if prev is not None else None,
            post_enabled=bool(post) if post is not None else None,
        )


@dataclass(frozen=True)
class HypervFirewallSnapshot:
    """Recorded pre-apply state of the WSL2 Hyper-V firewall setting."""

    vm_creator_id: str
    previous_enabled: bool | str | None
    previous_inbound: str | None
    previous_outbound: str | None
    post_enabled: bool | str | None = None
    post_inbound: str | None = None
    post_outbound: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vm_creator_id": self.vm_creator_id,
            "previous_enabled": self.previous_enabled,
            "previous_inbound": self.previous_inbound,
            "previous_outbound": self.previous_outbound,
            "post_enabled": self.post_enabled,
            "post_inbound": self.post_inbound,
            "post_outbound": self.post_outbound,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> HypervFirewallSnapshot:
        prev_en = payload.get("previous_enabled")
        if prev_en is not None and not isinstance(prev_en, bool):
            prev_en = str(prev_en)
        prev_in = payload.get("previous_inbound")
        prev_out = payload.get("previous_outbound")
        post_en = payload.get("post_enabled")
        if post_en is not None and not isinstance(post_en, bool):
            post_en = str(post_en)
        post_in = payload.get("post_inbound")
        post_out = payload.get("post_outbound")
        return cls(
            vm_creator_id=str(payload["vm_creator_id"]),
            previous_enabled=prev_en,
            previous_inbound=str(prev_in) if prev_in is not None else None,
            previous_outbound=str(prev_out) if prev_out is not None else None,
            post_enabled=post_en,
            post_inbound=str(post_in) if post_in is not None else None,
            post_outbound=str(post_out) if post_out is not None else None,
        )


@dataclass(frozen=True)
class IcaclsSnapshot:
    """Recorded pre-apply ACL backup for a user-owned path."""

    path_template: str
    backup_acl_path: str | None = None
    backup_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_template": self.path_template,
            "backup_acl_path": self.backup_acl_path,
            "backup_sha256": self.backup_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> IcaclsSnapshot:
        bak = payload.get("backup_acl_path")
        sha = payload.get("backup_sha256")
        return cls(
            path_template=str(payload["path_template"]),
            backup_acl_path=str(bak) if bak is not None else None,
            backup_sha256=str(sha) if sha is not None else None,
        )


@dataclass(frozen=True)
class PowercfgSnapshot:
    """Recorded pre-apply state of Windows hibernation."""

    previous_enabled: bool | None
    post_enabled: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"previous_enabled": self.previous_enabled, "post_enabled": self.post_enabled}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PowercfgSnapshot:
        prev = payload.get("previous_enabled")
        post = payload.get("post_enabled")
        return cls(
            previous_enabled=bool(prev) if prev is not None else None,
            post_enabled=bool(post) if post is not None else None,
        )


@dataclass(frozen=True)
class GitConfigSnapshot:
    """Recorded pre-apply state of a global git config key."""

    key: str
    existed: bool
    previous_value: str | None
    post_existed: bool | None = None
    post_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "existed": self.existed,
            "previous_value": self.previous_value,
            "post_existed": self.post_existed,
            "post_value": self.post_value,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> GitConfigSnapshot:
        prev = payload.get("previous_value")
        raw_post_ex = payload.get("post_existed")
        post_val = payload.get("post_value")
        return cls(
            key=str(payload["key"]),
            existed=bool(payload["existed"]),
            previous_value=str(prev) if prev is not None else None,
            post_existed=bool(raw_post_ex) if raw_post_ex is not None else None,
            post_value=str(post_val) if post_val is not None else None,
        )


@dataclass(frozen=True)
class FileSnapshot:
    """Recorded pre-apply snapshot of a structured configuration file."""

    path: str
    existed: bool
    sha256: str | None
    previous_content: str | None
    previous_bytes_b64: str | None = None
    post_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "existed": self.existed,
            "sha256": self.sha256,
            "previous_content": self.previous_content,
            "previous_bytes_b64": self.previous_bytes_b64,
            "post_sha256": self.post_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FileSnapshot:
        sha = payload.get("sha256")
        content = payload.get("previous_content")
        b64 = payload.get("previous_bytes_b64")
        post_sha = payload.get("post_sha256")
        return cls(
            path=str(payload["path"]),
            existed=bool(payload["existed"]),
            sha256=str(sha) if sha is not None else None,
            previous_content=str(content) if content is not None else None,
            previous_bytes_b64=str(b64) if b64 is not None else None,
            post_sha256=str(post_sha) if post_sha is not None else None,
        )


@dataclass(frozen=True)
class WslDistroSnapshot:
    """Recorded pre-apply state of a WSL2 distro's /etc/wsl.conf."""

    distro: str
    existed: bool
    previous_content: str = ""
    distro_guid: str | None = None
    post_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "distro": self.distro,
            "existed": self.existed,
            "previous_content": self.previous_content,
            "distro_guid": self.distro_guid,
            "post_sha256": self.post_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> WslDistroSnapshot:
        raw_prev = payload.get("previous_content")
        raw_guid = payload.get("distro_guid")
        raw_post = payload.get("post_sha256")
        return cls(
            distro=str(payload["distro"]),
            existed=bool(payload.get("existed", False)),
            previous_content=str(raw_prev) if raw_prev is not None else "",
            distro_guid=str(raw_guid) if raw_guid is not None else None,
            post_sha256=str(raw_post) if raw_post is not None else None,
        )
