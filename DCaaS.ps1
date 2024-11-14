# ForceNTHash functions

# Some constants
$AADConnectServiceName = "ADSync"
$AADConnectProcessName = "miiserver"

# Aug 21st 2023
function Install-ForceNTHash
{
<#
    .SYNOPSIS
    Installs ForceNTHash to the current computer.

    .DESCRIPTION
    Installs ForceNTHash to the current computer. 
    ForceNTHash enforces Windows legacy credential sync. Credentials are encrypted using ForceNTHash.pfx certificate.

    .EXAMPLE
    Install-AADIntForceNTHash
#>
    [cmdletbinding()]
    Param(
    [switch]$EnforceFullPasswordSync
    )
    Process
    {
        # Chech that running as administrator and that the service is running
        Test-LocalAdministrator -Throw | Out-Null

        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        $promptValue = Read-Host "Are you sure you wan't to install ForceNTHash to this computer? Type YES to continue or CTRL+C to abort"
        if($promptValue -eq "yes")
        {
            # We need to restart so we can inject before GetWindowsCredentialsSyncConfig is called
            Restart-Service $AADConnectServiceName

            # But still wait a couple of seconds
            Write-Warning "Sleeping for five seconds.."
            Start-Sleep -Seconds 5

            # Get the process id
            $process = Get-Process -Name $AADConnectProcessName -ErrorAction SilentlyContinue
            $processId = $process.Id
            
            # Inject the dll
            $result=Inject-DLL -ProcessID $processID -FileName "$PSScriptRoot\ForceNTHash.dll" -Function "Patch"
            Write-Verbose "Inject-DLL result: $result"
            
            if($result -like "*success*")
            {
                Write-Host "Installation successfully completed!"
                Write-Host "Windows legacy credentials sync is now enforced and credentials are encrypted with ForceNTHash certificate."

                if($EnforceFullPasswordSync)
                {
                    Initialize-FullPasswordSync
                }

                return
            }
            else
            {
                Write-Error "Installation failed: $result"
                return
            }
        }
    }
}

# Aug 18th 2023
function Remove-ForceNTHash
{
<#
    .SYNOPSIS
    Removes ForceNTHash from the current computer

    .DESCRIPTION
    Removes ForceNTHash from the current computer by restarting ADSync service.

    .EXAMPLE
    Remove-AADIntForceNTHash

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
    Service restarted and ForceNTHash removed.
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        Restart-Service $AADConnectServiceName

        Write-Host "Service restarted and ForceNTHash removed."
    }
}


# Aug 21st 2023
function Initialize-FullPasswordSync
{
<#
    .SYNOPSIS
    Enforces password hash sync of all users.

    .DESCRIPTION
    Enforces password hash sync of all users.

    .EXAMPLE
    Initialize-AADIntFullPasswordSync
#>
    [cmdletbinding()]
    Param()
    Process
    {
        $service = Get-Service -Name $AADConnectServiceName -ErrorAction SilentlyContinue
        if([String]::IsNullOrEmpty($service))
        {
            Write-Error "This command needs to be run on a computer with Azure AD Sync service (ADSync)"
            return
        }

        # ref: https://learn.microsoft.com/en-us/azure/active-directory-domain-services/tutorial-configure-password-hash-sync

        Import-Module "$(Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\AD Sync"          -Name "Location"        )\Bin\ADSync\ADSync.psd1"
        Import-Module "$(Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Azure AD Connect" -Name "InstallationPath")\AdSyncConfig\AdSyncConfig.psm1"

        $connectors = Get-ADSyncConnector

        if($connectors.Count -ne 2)
        {
            Throw "Connector count is not 2, can't automatically select connectors"
        }

        # Define the Azure AD Connect connector names and import the required PowerShell module
        $azureadConnector = (Get-ADSyncConnector | where Type -ne "AD").Name
        $adConnector      = (Get-ADSyncConnector | where Type -eq "AD").Name

        # Create a new ForceFullPasswordSync configuration parameter object then
        # update the existing connector with this new configuration
        $c = Get-ADSyncConnector -Name $adConnector
        $p = New-Object Microsoft.IdentityManagement.PowerShell.ObjectModel.ConfigurationParameter "Microsoft.Synchronize.ForceFullPasswordSync", String, ConnectorGlobal, $null, $null, $null
        $p.Value = 1
        $c.GlobalParameters.Remove($p.Name) | Out-Null
        $c.GlobalParameters.Add($p)         | Out-Null
        $c = Add-ADSyncConnector -Connector $c

        # Disable and re-enable Azure AD Connect to force a full password synchronization
        Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $false | Out-Null
        Set-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector -TargetConnector $azureadConnector -Enable $true  | Out-Null

        Write-Host "Full password sync enforced"
               
    }
}