"""Built-in tweaks and provenance for the `apps` category."""

from __future__ import annotations

from ...const import (
    DEFAULT_TESTED_BUILDS,
    MIN_SUPPORTED_BUILD,
    VSCODE_WINGET_ID,
    VSCODE_WSL_EXTENSION_ID,
)
from ...models import (
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
    WingetSpec,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "apps.install_vscode": TweakDefinition(
        tweak_id="apps.install_vscode",
        category="apps",
        title="Install Visual Studio Code (Windows User Scope) + Remote-WSL Extension",
        description=(
            "Installs Microsoft.VisualStudioCode in per-user scope via winget alongside the "
            "ms-vscode-remote.remote-wsl extension so `code .` inside WSL bash opens seamlessly."
        ),
        source_url="https://code.visualstudio.com/docs/remote/wsl",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(
            WingetSpec(
                package_id=VSCODE_WINGET_ID,
                scope="user",
                vscode_extensions=(VSCODE_WSL_EXTENSION_ID,),
            ),
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "apps.install_vscode": provenance_entry(
        "Provides Windows-side VS Code with Remote-WSL integration for WSL2 workflows.",
        "Microsoft Winget & VS Code CLI documentation (code --install-extension)",
        "Low risk: user-scope package installation without system policy changes.",
        "Installs VS Code (user scope) and ms-vscode-remote.remote-wsl extension.",
        "winget_package+vscode_extension",
        "Verified winget id Microsoft.VisualStudioCode and extension ms-vscode-remote.remote-wsl.",
    ),
}
