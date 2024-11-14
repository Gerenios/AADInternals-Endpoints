# This module contains functions to extract and update AADConnect sync credentials

# May 15th 2019
# Jul 26th 2024: Refactored to use service running as ADSync user
function Get-SyncCredentials
{
<#
    .SYNOPSIS
    Gets Azure AD Connect synchronization credentials

    .Description
    Extracts Azure Active Directory Connect crecentials from WID configuration database. MUST be run on AADConnect server
    as local administrator
  
    .Example
    Get-AADIntSyncCredentials

    Name                           Value
    ----                           -----
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com                                                      
    AADUserPassword                $.1%(lxZ&/kNZz[r
    ADDomain1                      company.com  
    ADUser1                        MSOL_4bc4a34e95fa
    ADUserPassword1                Q9@p(poz{#:kF_G)(s/Iy@8c*9(t;...
    ADDomain2                      business.net  
    ADUser2                        MSOL_4bc4a34e95fa
    ADUserPassword2                cE/Pj+4/MR6hW)2L_4P=H^hiq)pZhMb...

    .Example
    PS C:\>$synccredentials = Get-AADIntSyncCredentials -AsCredentials
    PS C:\>Get-AADIntAccessTokenForAADGraph -Credentials $synccredentials[0] -SaveToCache

    Tenant                               User                                            Resource                  Client               
    ------                               ----                                            --------                  ------               
    a5427106-ed71-4185-9481-221e2ebdfc6c Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com https://graph.windows.net 1b730954-1685-4b74...

#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$AsCredentials,
        [Parameter(Mandatory=$false)]
        [switch]$AsJson
    )
    Process
    {
        $serviceWMI = Get-WmiObject Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
        if(!$serviceWMI)
        {
            Throw "Service ADSync not found on this computer"
        }
        $ADSyncUser = $serviceWMI.StartName
        
        # Run as ADSync
        if((Get-CurrentUser) -ne $ADSyncUser)
        {
            # Check whether we are running in elevated session
            Test-LocalAdministrator -Throw | Out-Null
            
            Write-Verbose "Elevating to $ADSyncUser"
            $ADSyncCredentials = Get-LSASecrets -Account $ADSyncUser

            $cmdToRun = "Set-Location '$PSScriptRoot';. '.\CommonUtils.ps1';. '.\AADSyncSettings.ps1'; Get-SyncCredentials -AsJson"
                
            try
            {
                $credJson = Invoke-ScriptAs -Command $cmdToRun -Credentials $ADSyncCredentials.Credentials
                Write-Verbose "Invoke-ScriptAs response: $credJson"
                $retVal = ConvertFrom-Json -InputObject $credJson
            }
            catch
            {
                throw "Unable to get sync credentials as $ADSyncUser"
            }

        }
        else
        {
            # Add the encryption reference (should always be there)
            $ADSyncLocation = (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\AD Sync").Location
            Add-Type -path "$ADSyncLocation\Bin\mcrypt.dll"

            # Read the encrypt/decrypt key settings
            $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
            $SQLclient.Open()
            $SQLcmd = $SQLclient.CreateCommand()
            $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
            $SQLreader = $SQLcmd.ExecuteReader()
            $SQLreader.Read() | Out-Null
            $key_id = $SQLreader.GetInt32(0)
            $instance_id = $SQLreader.GetGuid(1)
            $entropy = $SQLreader.GetGuid(2)
            $SQLreader.Close()

            # Read the AD configuration data
            $ADConfigs=@()
            $SQLcmd = $SQLclient.CreateCommand()
            $SQLcmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
            $SQLreader = $SQLcmd.ExecuteReader()
            while($SQLreader.Read())
            {
                $ADConfig = $SQLreader.GetString(0)
                $ADCryptedConfig = $SQLreader.GetString(1)
                $ADConfigs += New-Object -TypeName psobject -Property @{"ADConfig" = $ADConfig; "ADCryptedConfig" = $ADCryptedConfig}
            }
            $SQLreader.Close()

            # Read the AAD configuration data
            $SQLcmd = $SQLclient.CreateCommand()
            $SQLcmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE subtype = 'Windows Azure Active Directory (Microsoft)'"
            $SQLreader = $SQLcmd.ExecuteReader()
            $SQLreader.Read() | Out-Null
            $AADConfig = $SQLreader.GetString(0)
            $AADCryptedConfig = $SQLreader.GetString(1)
            $SQLreader.Close()
            $SQLclient.Close()

            # Extract the data
            $attributes=[ordered]@{}
            $attributes["AADUser"]=([xml]$AADConfig).MAConfig.'parameter-values'.parameter[0].'#text'
            $attributes["AADUserPassword"]=""

            try
            {
                # Decrypt config data
                $KeyMgr = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager

                $KeyMgr.LoadKeySet($entropy, $instance_id, $key_id)
                #$key = $null
                #$KeyMgr.GetActiveCredentialKey([ref]$key)
                $key2 = $null
                $KeyMgr.GetKey(1, [ref]$key2)

                # Extract the encrypted data
                $n=1
                foreach($ADConfig in $ADConfigs)
                {
                    $ADDecryptedConfig = $null
                    $key2.DecryptBase64ToString($ADConfig.ADCryptedConfig, [ref]$ADDecryptedConfig)
                
                    $attributes["ADDomain$n"      ]=([xml]$ADConfig.ADConfig).'adma-configuration'.'forest-login-domain'
                    $attributes["ADUser$n"        ]=([xml]$ADConfig.ADConfig).'adma-configuration'.'forest-login-user'
                    $attributes["ADUserPassword$n"]=([xml]$ADDecryptedConfig).'encrypted-attributes'.attribute.'#text'
                
                    $n++
                }

                $AADDecryptedConfig = $null
                $key2.DecryptBase64ToString($AADCryptedConfig, [ref]$AADDecryptedConfig)
                $attributes["AADUserPassword"]=([xml]$AADDecryptedConfig).'encrypted-attributes'.attribute | Where name -eq "Password" | Select -ExpandProperty "#text"
                $retVal = [PSCustomObject]$attributes
            }
            catch
            {
                Write-Error "Could not load key set!"
            }

        }
        
        
        # Create credentials objects if requested
        if($AsJson)
        {
            return ($retVal | ConvertTo-Json -Compress)
        }
        if($AsCredentials)
        {
            $credentials = @()
            # There is only one AAD credentials
            $credentials += New-Object System.Management.Automation.PSCredential($retVal.AADUser, (ConvertTo-SecureString $retVal.AADUserPassword -AsPlainText -Force))

            # Loop through the on-prem AD credentials. Shouldn't be more than 100 :)
            for($n = 1 ; $n -lt 100 ; $n++)
            {
                if(![string]::IsNullOrEmpty($retVal."ADUser$n"))
                {
                   $userName = "$($retVal."ADDomain$n")\$($retVal."ADUser$n")"
                   $credentials += New-Object System.Management.Automation.PSCredential($userName, (ConvertTo-SecureString $retVal."ADUserPassword$n" -AsPlainText -Force))
                }
                else
                {
                    # No more on-prem AD credentials
                    break
                }
            }

            return @($credentials)
        }
        else
        {
            return $retVal
        }
            
    }
}

# May 16th 2019
# Jul 27th 2024: Updated to use reflection
function Update-SyncCredentials
{
<#
    .SYNOPSIS
    Updates Entra ID Connect synchronization credentials

    .Description
    Updates Entra ID Connect user's password to Entra ID and configuration database. MUST be run on AADConnect server
    as local administrator with Global Admin credentials to Entra ID
  
    .Example
    Update-AADIntSyncCredentials
    Password successfully updated to Entra ID and configuration sync client
    Remember to restart the sync service: Restart-Service ADSync

    .Example
    Update-AADIntSyncCredentials -RestartADSyncService
    Password successfully updated to Entra ID and configuration sync client

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to stop...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$AccessToken,
        [Switch]$RestartADSyncService,
        [Parameter(Mandatory=$False)]
        [pscredential]$Credentials
     )
    Process
    {
        # The service must be running
        if((Get-Service ADSync).Status -ne "Running")
        {
            Throw "Synchronization Service is not running."
        }

        # Get the Entra ID connector
        $connector = Get-ADSyncConnector -Identifier "b891884f-051e-4a83-95af-2544101c9083"

        # Get the connector connectivity properties
        $parameters   = $connector.GetType().GetField("connectivityParameters",[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static).GetValue($connector)
        $userProperty = $parameters | Where-Object Name -eq "UserName"
        $pwdProperty  = $parameters | Where-Object Name -eq "Password"

        # Use provided credentials
        if($Credentials)
        {
            $SyncUser    = $Credentials.UserName
            $NewPassword = $Credentials.GetNetworkCredential().Password
        }
        else
        {
            # Get from cache if not provided
            $AccessToken = Get-AccessTokenFromCache -AccessToken $AccessToken -ClientID "1b730954-1685-4b74-9bfd-dac224a7b894" -Resource "https://graph.windows.net"

            if([String]::IsNullOrEmpty($AccessToken))
            {
                Write-Error "No AccessToken provided!"
                return
            }
            # Admin user
            $AdminUser = (Read-Accesstoken -AccessToken $at).upn

            $SyncUser = $userProperty.Value

            Write-Verbose "Updating password for $SyncUser as $AdminUser"

            # Reset the account password in Entra ID and use the returned password
            $NewPassword = (Reset-ServiceAccount -AccessToken $AccessToken -ServiceAccount $SyncUser).Password
        }

        # Set the new password
        $pwdProperty.Value = $NewPassword

        # Update the password to configuration
        $result = Add-ADSyncConnector -Connector $connector

        Write-Host "Password successfully updated to Entra ID and sync client"

        # Restart the ADSync service if requested
        if($RestartADSyncService)
        {
            Restart-Service ADSync
        }
        else
        {
            Write-Host "Remember to restart the sync service: Restart-Service ADSync" -ForegroundColor Yellow
        }
    }
}

# May 17th 2019
function Set-ADSyncAccountPassword
{
<#
    .SYNOPSIS
    Sets the password of ADSync service account

    .Description
    Sets the password of ADSync service account to AD and WID configuration database. MUST be run on AADConnect server
    as domain administrator.
  
    .Example
    Set-AADIntADSyncAccountPassword -NewPassword 'Pa$$w0rd'
    Password successfully updated to AD and configuration database!
    Remember to restart the sync service: Restart-Service ADSync

    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Pa$$w0rd
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    .Example
    Set-AADIntADSyncAccountPassword -NewPassword 'Pa$$w0rd' -RestartADSyncService
    Password successfully updated to AD and configuration database!
    
    Name                           Value
    ----                           -----
    ADDomain                       company.com  
    ADUser                         MSOL_4bc4a34e95fa
    ADUserPassword                 Pa$$w0rd
    AADUser                        Sync_SRV01_4bc4a34e95fa@company.onmicrosoft.com
    AADUserPassword                $.1%(lxZ&/kNZz[r

    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to stop...
    WARNING: Waiting for service 'Microsoft Azure AD Sync (ADSync)' to start...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$NewPassword,
        [Switch]$RestartADSyncService,
        [Parameter(Mandatory=$false)]
        [switch]$force
     )
    Process
    {
        # Do the checks
        if((Check-Server -force $force) -eq $false)
        {
           return
        }

        # Add the encryption dll reference
        Add-Type -path "$(Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\AD Sync" -Name "Location")\Bin\mcrypt.dll"

        # Get the current configuration
        $SyncCreds = Get-SyncCredentials -force
        $SyncUser = $SyncCreds.ADUser

        Write-Verbose "Updating password for $SyncUser"

        # Reset the account password in AD
        try
        {
            Set-ADAccountPassword -Identity $SyncUser -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force)
        }
        catch
        {
            # There might be complexity etc. requirements
            throw $_
            return
        }

        # Escaping password for xml
        $NewPassword = [System.Security.SecurityElement]::Escape($NewPassword)

        # Create a new config
        $ADDecryptedConfig=@"
<encrypted-attributes>
 <attribute name="Password">$NewPassword</attribute>
</encrypted-attributes>
"@
        # Read the encrypt/decrypt key settings
        $SQLclient = new-object System.Data.SqlClient.SqlConnection -ArgumentList (Get-AADConfigDbConnection)
        $SQLclient.Open()
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
        $SQLreader = $SQLcmd.ExecuteReader()
        $SQLreader.Read() | Out-Null
        $key_id = $SQLreader.GetInt32(0)
        $instance_id = $SQLreader.GetGuid(1)
        $entropy = $SQLreader.GetGuid(2)
        $SQLreader.Close()

        # Load keys
        $KeyMgr = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
        $KeyMgr.LoadKeySet($entropy, $instance_id, $key_id)
        $key = $null
        $KeyMgr.GetActiveCredentialKey([ref]$key)
        $key2 = $null
        $KeyMgr.GetKey(1, [ref]$key2)

        # Encrypt
        $ADCryptedConfig = $null
        $key2.EncryptStringToBase64($ADDecryptedConfig,[ref]$ADCryptedConfig)

        # Write the updated AA password
        $SQLcmd = $SQLclient.CreateCommand()
        $SQLcmd.CommandText = "UPDATE mms_management_agent SET encrypted_configuration=@pwd WHERE ma_type = 'AD'"
        $SQLcmd.Parameters.AddWithValue("@pwd",$ADCryptedConfig) | Out-Null
        $UpdatedRows = $SQLcmd.ExecuteNonQuery() 
        $SQLclient.Close()
        
        if($UpdatedRows -ne 1)
        {
            Write-Error "Updated $UpdatedRows while should update 1. Could be error"
            return
        }

        Write-Host "Password successfully updated to AD and configuration database!"

        # Return        
        Get-SyncCredentials -force

        # Restart the ADSync service if requested
        if($RestartADSyncService)
        {
            Restart-Service ADSync
        }
        else
        {
            Write-Host "Remember to restart the sync service: Restart-Service ADSync" -ForegroundColor Yellow
        }
    }
}

# Gets the db connection string from the registry
# May 11th 2020
function Get-AADConfigDbConnection
{
    [cmdletbinding()]
    Param()
    Begin
    {
        # Create the connection string for the configuration database
        $parametersPath =    "HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters"
        $dBServer =          (Get-ItemProperty -Path $parametersPath).Server
        $dBName =            (Get-ItemProperty -Path $parametersPath).DBName
        $dBInstance =        (Get-ItemProperty -Path $parametersPath).SQLInstance
        $connectionString  = "Data Source=$dbServer\$dBInstance;Initial Catalog=$dBName"
        
        # If not using local WID, use ADSync account credentials
        if($dBServer -ne "(localdb)")
        {
            $connectionString += ";Integrated Security=true"
        }
    }
    Process
    {
        Write-Verbose "ConnectionString=$connectionString"

        return $connectionString
    }
}
