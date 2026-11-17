"""Built-in catalog of verified Windows and WSL tweaks."""

from .catalog import TWEAK_CATALOG, TWEAK_ID_ALIASES, get_all_tweaks, get_tweak, resolve_tweak_id
from .validation import CatalogValidationError, validate_catalog

__all__ = [
    "CatalogValidationError",
    "TWEAK_CATALOG",
    "TWEAK_ID_ALIASES",
    "get_all_tweaks",
    "get_tweak",
    "resolve_tweak_id",
    "validate_catalog",
]
