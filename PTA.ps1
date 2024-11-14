# This script contains utility functions for PTA

# Sets the certificate used by Azure AD Authentication Agent
# Mar 3rd 2020
# May 18th 2022: Fixed
function Set-PTACertificate
{
<#
    .SYNOPSIS
    Sets the certificate used by Azure AD Authentication Agent

    .DESCRIPTION
    Sets the certificate used by Azure AD Authentication Agent. 
    The certificate must be created with Register-AADIntPTAAgent function or exported with Export-AADIntProxyAgentCertificates.

    .Example
    Set-AADIntPTACertificate -PfxFileName server1.pfx -PfxPassword "password"
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$PfxFileName="PTA_client_certificate.pfx",
        [Parameter(Mandatory=$False)]
        [String]$PfxPassword
    )
    Process
    {
        # Check if the file exists
        if(-not (Test-Path $PfxFileName))
        {
            Write-Error "The file $PfxFileName does not exist!"
            return
        }

        # Import the certificate twice, otherwise PTAAgent has issues to access private keys
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-Item $PfxFileName).FullName, $PfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $cert.Import((Get-Item $PfxFileName).FullName, $PfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

        # Add certificate to Local Computer Personal store
        $myStore = Get-Item -Path "Cert:\LocalMachine\My"
        $myStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $myStore.Add($cert)
        $myStore.Close()

        # Get the Tenant Id and Instance Id
        $TenantId = $cert.Subject.Split("=")[1]
        
        foreach($extension in $cert.Extensions)
        {
            if($extension.Oid.Value -eq "1.3.6.1.4.1.311.82.1")
            {
                $InstanceID = [guid]$extension.RawData
                break
            }
        }

        # Set the registry value (the registy entry should already exists)
        Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\InstanceID to $InstanceID"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "InstanceID" -Value $InstanceID

        if(![string]::IsNullOrEmpty($TenantId))
        {
            Write-Verbose "Setting HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent\TenantID to $TenantId"
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Azure AD Connect Agents\Azure AD Connect Authentication Agent" -Name "TenantID" -Value $TenantId
        }

        # Set the certificate thumbprint to config file
        $configFile = "$env:ProgramData\Microsoft\Azure AD Connect Authentication Agent\Config\TrustSettings.xml"
        
        Write-Verbose "Setting the certificate thumbprint $($cert.Thumbprint) to $configFile"
        
        [xml]$TrustConfig = Get-Content $configFile
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.Thumbprint = $cert.Thumbprint
        $TrustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.IsInUserStore = "false"
        $TrustConfig.OuterXml | Set-Content $configFile

        # Set the read access to private key
        $ServiceUser="NT SERVICE\AzureADConnectAuthenticationAgent"

        # Create an accessrule for private key
        $AccessRule = New-Object Security.AccessControl.FileSystemAccessrule $ServiceUser, "read", allow
        
        # Give read permissions to the private key
        $keyName = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert).Key.UniqueName
        Write-Verbose "Private key: $keyName"

        $paths = @(
            "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$keyName"
            "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys\$keyName"
        )
        foreach($path in $paths)
        {
            if(Test-Path $path)
            {       
                Write-Verbose "Setting read access for ($ServiceUser) to the private key ($path)"
        
                try
                {
                    $permissions = Get-Acl -Path $path -ErrorAction SilentlyContinue
                    $permissions.AddAccessRule($AccessRule)
                    Set-Acl -Path $path -AclObject $permissions -ErrorAction SilentlyContinue
                }
                catch
                {
                    Write-Error "Could not give read access for ($ServiceUser) to the private key ($path)!"
                }
                break
            }
        }

        Write-Host "`nCertification information set, remember to (re)start the service."
    }
}