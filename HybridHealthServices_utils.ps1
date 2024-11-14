# Gets ADHybridHealthService agent information from the local computer
# May 26th 2021
function Get-HybridHealthServiceAgentInfo
{
<#
    .SYNOPSIS
    Gets ADHybridHealthService agent information from the local computer.

    .DESCRIPTION
    Gets ADHybridHealthService agent information from the local computer.

    .Parameter Service
    Which service's agent information to return. Can be one of "ADFS" or "Sync". Defaults to ADFS.

    .Example
    PS C:\>Get-AADIntHybridHealthServiceAgentInfo

    AgentKey        : 6Fk9SiL[redacted]Hw==
    TenantId        : 5d898b21-4478-4ee0-a2be-ad4dfb540b09
    ServiceId       : 59f626ab-92cd-4658-b12f-12a604f5f1c2
    ServiceMemberId : 0bfc0715-1ed2-44c7-89ec-bf7842cc4575
    MachineId       : 279a0323-4647-494c-ac3a-fc13545f3c33
#>
    [cmdletbinding()]
    Param(
        [ValidateSet("ADFS","Sync")]
        [String]$Service="ADFS"
    )
    Begin
    {
        # Add the required assembly and entropy
        Add-Type -AssemblyName System.Security
        $entropy = [text.encoding]::Unicode.getBytes("ra4k1Q0qHdYSZfqGxgnFB3c6Z025w4IU")
    }
    Process
    {
        $attributes = [ordered]@{}
        try
        {
            # Decrypt the agent key
            $encAgentKey            = Convert-B64ToByteArray -B64   (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent" -Name "AgentKey")
            $attributes["AgentKey"] = Convert-ByteArrayToB64 -Bytes ([Security.Cryptography.ProtectedData]::Unprotect([byte[]]$encAgentKey, $entropy, 'CurrentUser'))

            # Get other relevant agent information
            $attributes["TenantId"]        = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent"                              -Name "TenantId"
            $attributes["ServiceId"]       = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\$Service"                     -Name "ServiceId"
            $attributes["ServiceMemberId"] = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\ADHealthAgent\$Service"                     -Name "ServiceMemberId"
            $attributes["MachineId"]       = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent" -Name "MachineIdentity"
            $attributes["Server"]          = $env:COMPUTERNAME
        }
        catch
        {
            Throw "Must be run as Local Administrator and on the computer where the agent is installed!`nGot error: $($_.Exception.Message)"
        }

        # Return
        New-Object -TypeName psobject -Property $attributes
    }
}
