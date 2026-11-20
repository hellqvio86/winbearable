<#
.SYNOPSIS
    Locally signs winbearable release binaries using Authenticode (never run in GitHub Actions).
.DESCRIPTION
    Signs one or more target binaries (default: dist\wb.exe) using a code-signing certificate
    loaded into memory from Bitwarden CLI (`bw get item`), a local .pfx file, or Cert:\CurrentUser\My.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$TargetPaths = @("dist\wb.exe"),

    [string]$BitwardenItem = "winbearable-local-signing",

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
    $bwCmd = Get-Command bw -ErrorAction SilentlyContinue
    if (-not $bwCmd) {
        throw "Bitwarden CLI ('bw') not found in PATH. Pass -PfxPath or -Thumbprint, or open a new shell with bw."
    }
    $rawItem = & $bwCmd.Source get item $BitwardenItem
    if ($LASTEXITCODE -ne 0 -or -not $rawItem) {
        throw "Failed to read Bitwarden item '$BitwardenItem'. Ensure 'bw unlock' and BW_SESSION are set."
    }
    $item = $rawItem | ConvertFrom-Json
    $pfxB64 = ($item.fields | Where-Object { $_.name -eq "pfx_base64" } | Select-Object -First 1).value
    $pfxPw = ($item.fields | Where-Object { $_.name -eq "pfx_password" } | Select-Object -First 1).value
    if (-not $pfxB64 -or -not $pfxPw) {
        throw "Bitwarden item '$BitwardenItem' must contain 'pfx_base64' and 'pfx_password' fields."
    }
    $pfxBytes = [Convert]::FromBase64String([string]$pfxB64)
    $secPw = ConvertTo-SecureString -String ([string]$pfxPw) -AsPlainText -Force
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes, $secPw)
}

try {
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
} finally {
    if ($cert) {
        $cert.Dispose()
    }
}
