# ADR 0005: WSL Host & Distro Transaction Boundary

- **Status:** Accepted
- **Scope:** `src/winbearable/engine/phases.py`, `src/winbearable/wsl/`

## Decision

Profile-driven `.wslconfig` and per-distro `/etc/wsl.conf` changes run inside `MutateWslPhase` within the same `RunRecord` transaction after `MutateTweaksPhase`, recording `.wslconfig.bak` and `WslDistroSnapshot` before mutation. Internal Docker Desktop distros (`docker-desktop`, `docker-desktop-data`) are excluded.

## Consequences

- A WSL failure triggers compensation of both WSL changes and already-applied Windows tweaks.
- Distro names are strictly validated before invoking `wsl.exe`.
