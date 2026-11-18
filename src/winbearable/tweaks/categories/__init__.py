"""Per-category tweak specifications and provenance."""

from __future__ import annotations

from . import (
    ai,
    apps,
    bloat,
    dev,
    edge,
    explorer,
    hardening,
    input,
    onedrive,
    power,
    privacy,
    search,
    services,
    start,
    taskbar,
    telemetry,
    terminal,
)

CATEGORY_MODULES = (
    apps,
    onedrive,
    search,
    start,
    taskbar,
    explorer,
    ai,
    privacy,
    hardening,
    bloat,
    telemetry,
    input,
    terminal,
    dev,
    power,
    edge,
    services,
)

__all__ = ["CATEGORY_MODULES"]
