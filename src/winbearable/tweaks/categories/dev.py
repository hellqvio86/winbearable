"""Built-in tweaks and provenance for the `dev` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    DEFAULT_WSL_DISTRO,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ...models import (
    FileSpec,
    GitConfigSpec,
    IcaclsUserOnlySpec,
    OptionalFeatureSpec,
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
    WingetSpec,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "dev.long_paths": TweakDefinition(
        tweak_id="dev.long_paths",
        category="dev",
        title="Enable Win32 Long Paths (> 260 chars)",
        description="Sets HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem\\LongPathsEnabled=1.",
        source_url="https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\FileSystem",
                value_name="LongPathsEnabled",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "dev.developer_mode": TweakDefinition(
        tweak_id="dev.developer_mode",
        category="dev",
        title="Enable Windows Developer Mode (Unprivileged Symlinks)",
        description="Sets AllowDevelopmentWithoutDevLicense=1 (opt-in; slightly enlarges sideloading/symlink surface).",
        source_url="https://learn.microsoft.com/en-us/windows/apps/get-started/enable-your-device-for-development",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
                value_name="AllowDevelopmentWithoutDevLicense",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "dev.git_sane_defaults": TweakDefinition(
        tweak_id="dev.git_sane_defaults",
        category="dev",
        title="Configure Sane Global Git Defaults (LF, Symlinks, LongPaths, main)",
        description=(
            "Sets core.autocrlf=input, core.eol=lf, core.symlinks=true, core.longpaths=true, init.defaultBranch=main."
        ),
        source_url="https://git-scm.com/docs/git-config",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        git_config_specs=(
            GitConfigSpec(key="core.autocrlf", value="input"),
            GitConfigSpec(key="core.eol", value="lf"),
            GitConfigSpec(key="core.symlinks", value="true"),
            GitConfigSpec(key="core.longpaths", value="true"),
            GitConfigSpec(key="init.defaultBranch", value="main"),
        ),
    ),
    "dev.fix_ssh_key_permissions": TweakDefinition(
        tweak_id="dev.fix_ssh_key_permissions",
        category="dev",
        title="Restrict %USERPROFILE%\\.ssh ACLs to Current User Only",
        description="Uses icacls.exe to remove inherited broad permissions on %USERPROFILE%\\.ssh.",
        source_url="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        icacls_specs=(IcaclsUserOnlySpec(path_template=r"%USERPROFILE%\.ssh"),),
    ),
    "dev.enable_windows_containers": TweakDefinition(
        tweak_id="dev.enable_windows_containers",
        category="dev",
        title="Enable Windows Containers Optional Feature",
        description=(
            "Enables the Windows `Containers` optional feature via dism.exe so Docker Desktop "
            "can run Windows containers (Pro/Enterprise/Education; requires reboot)."
        ),
        source_url="https://learn.microsoft.com/en-us/virtualization/windowscontainers/quick-start/set-up-environment",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        requires_reboot=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        feature_specs=(OptionalFeatureSpec(feature_name="Containers", enabled=True),),
    ),
    "dev.vscode_settings_defaults": TweakDefinition(
        tweak_id="dev.vscode_settings_defaults",
        category="dev",
        title="Configure VS Code Developer & WSL Defaults",
        description=(
            "Sets telemetry.telemetryLevel='off', files.eol='\\n', and "
            f"terminal.integrated.defaultProfile.windows='{DEFAULT_WSL_DISTRO} (WSL)' "
            "in %APPDATA%\\Code\\User\\settings.json (refuses if JSONC contains comments)."
        ),
        source_url="https://code.visualstudio.com/docs/terminal/profiles",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        file_specs=(
            FileSpec(
                path_template=r"%APPDATA%\Code\User\settings.json",
                file_format="jsonc",
                desired_keys={
                    "telemetry.telemetryLevel": "off",
                    "terminal.integrated.defaultProfile.windows": f"{DEFAULT_WSL_DISTRO} (WSL)",
                    "files.eol": "\n",
                },
            ),
        ),
    ),
    "dev.case_sensitive_dirs": TweakDefinition(
        tweak_id="dev.case_sensitive_dirs",
        category="dev",
        title="Enable NTFS Case-Sensitive Directories",
        description=(
            "Runs fsutil.exe file setCaseSensitiveInfo <dir> enable for directories listed in "
            '[params."dev.case_sensitive_dirs"].directories (revert refuses non-empty directories).'
        ),
        source_url="https://learn.microsoft.com/en-us/windows/wsl/case-sensitivity",
        risk=RiskLevel.MEDIUM,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        parameterized=True,
    ),
    "dev.terminal_settings_defaults": TweakDefinition(
        tweak_id="dev.terminal_settings_defaults",
        category="dev",
        title="Configure Windows Terminal Developer Defaults",
        description=(
            "Sets copyOnSelect=true (and optional defaultProfile / font_face from [params]) "
            "in Windows Terminal settings.json."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/terminal/customize-settings/interaction",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        file_specs=(
            FileSpec(
                path_template=r"%LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json",
                file_format="json",
                desired_keys={"copyOnSelect": True},
            ),
        ),
    ),
    "dev.install_nerd_font_user": TweakDefinition(
        tweak_id="dev.install_nerd_font_user",
        category="dev",
        title="Install JetBrainsMono Nerd Font (Per-User)",
        description="Installs DEVCOM.JetBrainsMonoNerdFont in user scope via winget.",
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="DEVCOM.JetBrainsMonoNerdFont", scope="user"),),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "dev.long_paths": provenance_entry(
        "Enables Win32 long paths (> 260 chars) in NTFS/Win32 APIs.",
        "Microsoft Learn: Maximum Path Length Limitation (LongPathsEnabled)",
        "Low risk: standard developer filesystem toggle.",
        "Tools and Python packages with deep paths work without MAX_PATH errors.",
        "registry_value",
        "Verified HKLM Control\\FileSystem LongPathsEnabled=1.",
    ),
    "dev.developer_mode": provenance_entry(
        "Enables Windows Developer Mode (allows unprivileged symlinks and sideloading).",
        "Microsoft Learn: Enable your device for development (AppModelUnlock)",
        "Medium risk: enlarges local app sideloading/symlink surface; opt-in only.",
        "Permits git/dev tools to create symlinks without Administrator elevation.",
        "registry_value",
        "Verified HKLM AppModelUnlock AllowDevelopmentWithoutDevLicense=1.",
    ),
    "dev.git_sane_defaults": provenance_entry(
        (
            "Configures sane cross-platform git global defaults "
            "(autocrlf=input, eol=lf, symlinks=true, longpaths=true, defaultBranch=main)."
        ),
        "Git Documentation: git-config",
        "Low risk: per-user git global config; never touches user.name or user.email.",
        "Prevents CRLF line-ending corruption across Windows and WSL2.",
        "git_config",
        "Verified git.exe config --global set/get/unset roundtrip.",
    ),
    "dev.fix_ssh_key_permissions": provenance_entry(
        "Restricts %USERPROFILE%\\.ssh ACLs to the current user only via icacls.exe.",
        "Microsoft Learn: icacls /inheritance:r /grant:r",
        "Low risk: fixes overly permissive Windows SSH key ACLs.",
        "Only the current user can read/write %USERPROFILE%\\.ssh.",
        "icacls",
        "Verified icacls.exe /inheritance:r /grant:r syntax.",
    ),
    "dev.enable_windows_containers": provenance_entry(
        "Enables the Windows Containers optional feature required for Windows-container Docker images.",
        "Microsoft Learn: Prepare Windows operating system containers",
        "Medium risk: enables an OS optional feature and requires a reboot; reversible via dism.",
        "Allows Docker Desktop to switch to Windows containers (Pro/Enterprise/Education).",
        "dism_optional_feature",
        "Verified Containers feature name against Microsoft Learn.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "dev.vscode_settings_defaults": provenance_entry(
        (
            "Configures VS Code per-user defaults: telemetry.telemetryLevel='off', "
            "files.eol='\\n', and terminal.integrated.defaultProfile.windows='Ubuntu (WSL)'."
        ),
        "Visual Studio Code Documentation: Terminal Profiles & Settings",
        "Low risk: per-user JSON merge with SHA-256 drift guard; refuses to overwrite JSONC with comments.",
        "Disables VS Code telemetry, defaults to LF line endings, and opens WSL in the integrated terminal.",
        "file_config",
        "Verified merge, comment-refusal, and snapshot/rollback via FileConfigOperationAdapter.",
    ),
    "dev.case_sensitive_dirs": provenance_entry(
        "Enables per-directory NTFS case sensitivity via fsutil.exe for paths in [params].",
        "Microsoft Learn: Case sensitivity in WSL",
        "Medium risk: revert refuses if directory is non-empty.",
        "Selected directories preserve case-sensitive filenames like Linux filesystems.",
        "fsutil_case_sensitive",
        "Verified fsutil.exe file setCaseSensitiveInfo / queryCaseSensitiveInfo syntax.",
    ),
    "dev.terminal_settings_defaults": provenance_entry(
        "Configures Windows Terminal copyOnSelect=true (and optional defaultProfile / font_face from [params]).",
        "Microsoft Learn: Windows Terminal interaction settings",
        "Low risk: per-user JSON merge with SHA-256 drift guard and full rollback.",
        "Copies selected text automatically in Windows Terminal.",
        "file_config",
        "Verified merge and snapshot/rollback via FileConfigOperationAdapter.",
    ),
    "dev.install_nerd_font_user": provenance_entry(
        "Installs JetBrainsMono Nerd Font per-user via winget.",
        "Winget Community Repository: DEVCOM.JetBrainsMonoNerdFont",
        "Low risk: per-user winget package install; uninstallable via rollback or winget.",
        "Provides Nerd Font glyphs for terminal prompts and editors.",
        "winget_package",
        "Verified package ID DEVCOM.JetBrainsMonoNerdFont via winget search.",
    ),
}
