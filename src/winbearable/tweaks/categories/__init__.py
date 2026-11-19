"""Per-category tweak specifications and provenance."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from ...models import TweakDefinition, TweakProvenance
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


class CategoryModule(Protocol):
    """Protocol for tweak category modules exporting TWEAKS and PROVENANCE mappings."""

    @property
    def TWEAKS(self) -> Mapping[str, TweakDefinition]: ...

    @property
    def PROVENANCE(self) -> Mapping[str, TweakProvenance]: ...


def _cat(mod: CategoryModule) -> CategoryModule:
    return mod


CATEGORY_MODULES: tuple[CategoryModule, ...] = (
    _cat(apps),
    _cat(onedrive),
    _cat(search),
    _cat(start),
    _cat(taskbar),
    _cat(explorer),
    _cat(ai),
    _cat(privacy),
    _cat(hardening),
    _cat(bloat),
    _cat(telemetry),
    _cat(input),
    _cat(terminal),
    _cat(dev),
    _cat(power),
    _cat(edge),
    _cat(services),
)

__all__ = ["CATEGORY_MODULES", "CategoryModule"]
