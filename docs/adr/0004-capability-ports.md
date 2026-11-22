# ADR 0004: Interface-Segregated Capability Ports

- **Status:** Accepted
- **Scope:** `src/winbearable/backends/ports.py`, `src/winbearable/operations/`

## Decision

Operation adapters and engine helpers depend on narrow `typing.Protocol` capability ports (`AclPort`, `ServicePort`, `TaskPort`, `FeaturePort`, `FirewallPort`, `AuditPolicyPort`, `PackagePort`, `ProcessAndOneDrivePort`, `GitAndPowerPort`, `WslHostPort`, `OutcomePort`, `RegistryBackupPort`) rather than the monolithic `SystemBackend` interface. `PORT_PROTOCOLS` + `typing.get_protocol_members()` serve as the single runtime/static source of truth.

## Consequences

- Adapters can be unit-tested with minimal fakes implementing only the required port.
- Removing or renaming a Protocol method cannot leave a stale runtime contract list.
