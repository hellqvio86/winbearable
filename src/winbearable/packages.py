"""Allowlisted winget package catalog and preset groups (PKG-01, PKG-02)."""

from dataclasses import dataclass


@dataclass(frozen=True)
class PackageDefinition:
    """Allowlisted winget package metadata."""

    name: str
    winget_id: str
    scope: str
    source_url: str
    version_pin: str | None = None
    requires_admin: bool = False


PACKAGE_CATALOG: dict[str, PackageDefinition] = {
    "windows-terminal": PackageDefinition(
        name="windows-terminal",
        winget_id="Microsoft.WindowsTerminal",
        scope="user",
        source_url="https://learn.microsoft.com/en-us/windows/terminal/install",
    ),
    "git": PackageDefinition(
        name="git",
        winget_id="Git.Git",
        scope="user",
        source_url="https://git-scm.com/download/win",
    ),
    "vscode": PackageDefinition(
        name="vscode",
        winget_id="Microsoft.VisualStudioCode",
        scope="user",
        source_url="https://code.visualstudio.com/docs/remote/wsl",
    ),
    "powertoys": PackageDefinition(
        name="powertoys",
        winget_id="Microsoft.PowerToys",
        scope="user",
        source_url="https://learn.microsoft.com/en-us/windows/powertoys/install",
    ),
    "everything": PackageDefinition(
        name="everything",
        winget_id="voidtools.Everything",
        scope="user",
        source_url="https://www.voidtools.com/",
    ),
    "flow-launcher": PackageDefinition(
        name="flow-launcher",
        winget_id="Flow-Launcher.Flow-Launcher",
        scope="user",
        source_url="https://www.flowlauncher.com/",
    ),
    "7zip": PackageDefinition(
        name="7zip",
        winget_id="7zip.7zip",
        scope="user",
        source_url="https://www.7-zip.org/",
    ),
    "wezterm": PackageDefinition(
        name="wezterm",
        winget_id="wez.wezterm",
        scope="user",
        source_url="https://wezfurlong.org/wezterm/",
    ),
    "komorebi": PackageDefinition(
        name="komorebi",
        winget_id="LGUG2Z.komorebi",
        scope="user",
        source_url="https://lgug2z.github.io/komorebi/",
    ),
    "whkd": PackageDefinition(
        name="whkd",
        winget_id="LGUG2Z.whkd",
        scope="user",
        source_url="https://github.com/LGUG2Z/whkd",
    ),
    "glazewm": PackageDefinition(
        name="glazewm",
        winget_id="glzr-io.glazewm",
        scope="user",
        source_url="https://github.com/glzr-io/glazewm",
    ),
    "kanata-gui": PackageDefinition(
        name="kanata-gui",
        winget_id="jtroo.kanata_gui",
        scope="user",
        source_url="https://github.com/jtroo/kanata",
    ),
    "ripgrep": PackageDefinition(
        name="ripgrep",
        winget_id="BurntSushi.ripgrep.MSVC",
        scope="user",
        source_url="https://github.com/BurntSushi/ripgrep",
    ),
    "fd": PackageDefinition(
        name="fd",
        winget_id="sharkdp.fd",
        scope="user",
        source_url="https://github.com/sharkdp/fd",
    ),
    "jq": PackageDefinition(
        name="jq",
        winget_id="jqlang.jq",
        scope="user",
        source_url="https://jqlang.github.io/jq/",
    ),
    "jetbrains-mono-nerd-font": PackageDefinition(
        name="jetbrains-mono-nerd-font",
        winget_id="DEVCOM.JetBrainsMonoNerdFont",
        scope="user",
        source_url="https://www.nerdfonts.com/",
    ),
    "sysmon": PackageDefinition(
        name="sysmon",
        winget_id="Microsoft.Sysinternals.Sysmon",
        scope="machine",
        source_url="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        requires_admin=True,
    ),
}

PACKAGE_PRESETS: dict[str, tuple[str, ...]] = {
    "dev-core": ("windows-terminal", "git", "vscode"),
    "launcher": ("everything", "flow-launcher"),
    "tiling-wm": ("komorebi", "whkd", "glazewm"),
    "fonts": ("jetbrains-mono-nerd-font",),
}
