<#
.SYNOPSIS
    Locally signs winbearable release binaries using Authenticode (never run in GitHub Actions).
.DESCRIPTION
    Signs one or more target binaries (default: dist\wb.exe) using either a code-signing
    certificate in Cert:\CurrentUser\My or a local .pfx file (stored outside git, e.g. in Bitwarden).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$TargetPaths = @("dist\wb.exe"),

    [string]$Thumbprint = "",

    [string]$PfxPath = "",

    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$cert = $null
if ($PfxPath) {
    if (-not (Test-Path -LiteralPath $PfxPath)) {
        throw "PFX file not found: $PfxPath"
    }
    $pw = Read-Host -Prompt "Enter PFX password" -AsSecureString
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Resolve-Path -LiteralPath $PfxPath).Path,
        $pw
    )
} elseif ($Thumbprint) {
    $cert = Get-ChildItem "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction Stop
} else {
    $cert = Get-ChildItem "Cert:\CurrentUser\My" -CodeSigningCert |
        Where-Object { $_.Subject -like "*winbearable*" } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1
    if (-not $cert) {
        throw "No winbearable code-signing certificate found in Cert:\CurrentUser\My. Pass -Thumbprint or -PfxPath."
    }
}

foreach ($path in $TargetPaths) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Target binary not found: $path"
    }
    $sig = Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($sig.Status -eq "UnknownError") {
        throw "Signing failed for ${path}: $($sig.StatusMessage)"
    }
    Write-Output ("Signed {0} -> Status={1} Thumbprint={2}" -f $path, $sig.Status, $cert.Thumbprint)
}
