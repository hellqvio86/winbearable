"""Operation adapter abstraction decoupling the domain engine from concrete OS side effects."""

from typing import Protocol

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .const import ACTION_DELETE
from .models import PlannedOperation, TweakDefinition


class OperationAdapter(Protocol):
    """Contract for inspecting and planning a single category of side-effecting operations."""

    kind: str

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        """Return (planned_operations, drifted_reasons, unverified_reasons) for this operation kind."""


class ServiceOperationAdapter:
    """Adapter for Windows service start-type operations."""

    kind = "service"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for svc_spec in tweak.service_specs:
            actual_start = system.get_service_start_type(registry, svc_spec.service_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=svc_spec.service_name,
                    action="configure",
                    before_state=str(actual_start) if actual_start is not None else "<unknown>",
                    after_state=str(svc_spec.start_type),
                    reversible=True,
                )
            )
            if actual_start != svc_spec.start_type:
                drifted.append(
                    f"{svc_spec.registry_key_path} [Start]: {actual_start} -> {svc_spec.start_type} (REG_DWORD)"
                )
        return ops, drifted, []


class TaskOperationAdapter:
    """Adapter for Windows Scheduled Task enable/disable operations."""

    kind = "scheduled_task"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for task_spec in tweak.task_specs:
            actual_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=task_spec.task_path,
                    action="enable" if task_spec.enabled else "disable",
                    before_state=str(actual_enabled) if actual_enabled is not None else "<unverified>",
                    after_state=str(task_spec.enabled),
                    reversible=True,
                )
            )
            if actual_enabled is None:
                unverified.append(f"schtasks {task_spec.task_path}: <unverified/missing>")
            elif actual_enabled != task_spec.enabled:
                drifted.append(
                    f"schtasks {task_spec.task_path}: enabled={actual_enabled} -> enabled={task_spec.enabled}"
                )
        return ops, drifted, unverified


class FeatureOperationAdapter:
    """Adapter for Windows DISM optional feature operations."""

    kind = "optional_feature"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for feat_spec in tweak.feature_specs:
            actual_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=feat_spec.feature_name,
                    action="enable" if feat_spec.enabled else "disable",
                    before_state=str(actual_feat) if actual_feat is not None else "<unverified>",
                    after_state=str(feat_spec.enabled),
                    reversible=True,
                )
            )
            if actual_feat is None:
                unverified.append(f"dism feature {feat_spec.feature_name}: <unverified/missing>")
            elif actual_feat != feat_spec.enabled:
                drifted.append(
                    f"dism feature {feat_spec.feature_name}: enabled={actual_feat} -> enabled={feat_spec.enabled}"
                )
        return ops, drifted, unverified


class WingetOperationAdapter:
    """Adapter for winget package and VS Code extension installations."""

    kind = "winget_package"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for winget_spec in tweak.winget_specs:
            installed = system.is_winget_package_installed(winget_spec.package_id)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=f"{winget_spec.package_id} (scope={winget_spec.scope})",
                    action="install",
                    before_state="installed" if installed else "<missing>",
                    after_state="installed",
                    reversible=True,
                )
            )
            for ext_id in winget_spec.vscode_extensions:
                ext_installed = system.is_vscode_extension_installed(ext_id)
                ops.append(
                    PlannedOperation(
                        operation_type="vscode_extension",
                        target=ext_id,
                        action="install",
                        before_state="installed" if ext_installed else "<missing>",
                        after_state="installed",
                        reversible=True,
                    )
                )
            if not installed:
                ext_str = (
                    f" + extensions {list(winget_spec.vscode_extensions)}" if winget_spec.vscode_extensions else ""
                )
                drifted.append(
                    f"winget package {winget_spec.package_id} (scope={winget_spec.scope}): "
                    f"<missing> -> installed{ext_str}"
                )
        return ops, drifted, []


class ProcessStopOperationAdapter:
    """Adapter for graceful/forced process termination operations."""

    kind = "process_stop"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for proc_name in tweak.stop_processes:
            running = system.is_process_running(proc_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=proc_name,
                    action="stop",
                    before_state="running" if running else "stopped",
                    after_state="stopped",
                    reversible=False,
                )
            )
            if running:
                drifted.append(f"Process {proc_name}: running -> stopped")
        return ops, drifted, []


# Explicit dependency-ordered adapter chain
OPERATION_ADAPTERS: tuple[OperationAdapter, ...] = (
    ServiceOperationAdapter(),
    TaskOperationAdapter(),
    FeatureOperationAdapter(),
    WingetOperationAdapter(),
    ProcessStopOperationAdapter(),
)


def inspect_non_registry_operations(
    tweak: TweakDefinition,
    registry: RegistryBackend,
    system: SystemBackend,
) -> tuple[list[PlannedOperation], list[str], list[str]]:
    """Inspect all non-registry operations for a tweak via ordered OperationAdapters."""
    all_ops: list[PlannedOperation] = []
    all_drifted: list[str] = []
    all_unverified: list[str] = []
    for adapter in OPERATION_ADAPTERS:
        ops, drifted, unverified = adapter.inspect(tweak, registry, system)
        all_ops.extend(ops)
        all_drifted.extend(drifted)
        all_unverified.extend(unverified)
    return all_ops, all_drifted, all_unverified


def format_registry_op(
    full_key_path: str,
    display_value_name: str,
    action: str,
    current_value: object,
    target_value: object,
    irreversible: bool,
) -> PlannedOperation:
    """Construct a PlannedOperation for a single registry spec."""
    return PlannedOperation(
        operation_type="registry",
        target=f"{full_key_path} [{display_value_name}]",
        action=action,
        before_state=repr(current_value) if current_value is not None else "<absent>",
        after_state="<deleted>" if action == ACTION_DELETE else repr(target_value),
        reversible=not irreversible,
    )
