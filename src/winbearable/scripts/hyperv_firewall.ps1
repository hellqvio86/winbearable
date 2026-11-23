param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("get", "set")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$')]
    [string]$VmCreatorId,

    [ValidateSet("True", "False", "NotConfigured")]
    [string]$Enabled = "True",

    [ValidateSet("Block", "Allow")]
    [string]$DefaultInboundAction = "Block",

    [ValidateSet("Block", "Allow")]
    [string]$DefaultOutboundAction = "Allow"
)

try {
    if ($Action -eq "set") {
        if ($Enabled -eq "NotConfigured") {
            Set-NetFirewallHyperVVMSetting -Name $VmCreatorId `
                -Enabled NotConfigured `
                -DefaultInboundAction $DefaultInboundAction `
                -DefaultOutboundAction $DefaultOutboundAction `
                -ErrorAction Stop
        } else {
            $enabledBool = $Enabled -eq "True"
            Set-NetFirewallHyperVVMSetting -Name $VmCreatorId `
                -Enabled $enabledBool `
                -DefaultInboundAction $DefaultInboundAction `
                -DefaultOutboundAction $DefaultOutboundAction `
                -ErrorAction Stop
        }
    }

    Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name $VmCreatorId -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LoopbackEnabled |
        ConvertTo-Json -Compress
} catch {
    @{ error = $_.Exception.Message } | ConvertTo-Json -Compress
    exit 1
}
