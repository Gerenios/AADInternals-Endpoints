# This file contains functions for Microsoft App Proxy

# Export proxy agent certificates from the local computer
# Mar 8th 2022
# Aug 17th 2022: Added support for exporting from NETWORK SERVICE personal store
function Export-ProxyAgentCertificates
{
    <#
    .SYNOPSIS
    Export certificates of all MS App Proxy agents from the local computer.

    .DESCRIPTION
    Export certificates of all MS App Proxy agents from the local computer.
    The filename of the certificate is <server FQDN>_<tenant id>_<agent id>_<cert thumbprint>.pfx

    .Example
    Export-AADIntProxyAgentCertificates

    WARNING: Elevating to LOCAL SYSTEM. You MUST restart PowerShell to restore PTA01\Administrator rights.

    Certificate saved to: PTA01.company.com_ea664074-37dd-4797-a676-b0cf6fdafcd4_4b6ffe82-bfe2-4357-814c-09da95399da7_A3457AEAE25D4C513BCF37CB138628772BE1B52.pfx
    
    #>
    [cmdletbinding()]
    Param()

    Process
    {
        # Get all certificates from LocalMachine Personal store
        $certificates = @(Get-Item Cert:\LocalMachine\My\*)

        # Internal function to parse PTA & Provisioning agent configs
        function Parse-ConfigCert
        {
            [cmdletbinding()]
            Param(
                [String]$ConfigPath
            )
            Process
            {
                # Check if we have a PTA or provisioning agent configuration and get the certificate if stored in NETWORK SERVICE personal store
                [xml]$trustConfig = Get-Content "$env:ProgramData\Microsoft\$ConfigPath\Config\TrustSettings.xml" -ErrorAction SilentlyContinue
        
                if($trustConfig)
                {
                    $thumbPrint = $trustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.Thumbprint

                    # Check where the certificate is stored
                    if($trustConfig.ConnectorTrustSettingsFile.CloudProxyTrust.IsInUserStore.ToLower().equals("true"))
                    {
                        # Certificate is stored in NETWORK SERVICE personal store so we need to parse it from there
                        Write-Verbose "Parsing certificate: $($thumbPrint)"

                        Parse-CertBlob -Data (Get-BinaryContent "$env:windir\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\$thumbPrint")
                    }

                } 
            }
        }
        
        if($PTACert = Parse-ConfigCert -ConfigPath "Azure AD Connect Authentication Agent")
        {
            $binCert = $PTACert.DER
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$binCert)
            $PTAKeyName = $PTACert.KeyIdentifier
            $certificates += $certificate
        }

        if($ProvCert = Parse-ConfigCert -ConfigPath "Azure AD Connect Provisioning Agent")
        {
            $binCert = $ProvCert.DER
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$binCert)
            $ProvKeyName = $ProvCert.KeyIdentifier
            $certificates += $certificate
        }

        foreach($certificate in $certificates)
        {
            Write-Verbose "Reading certificate: $($certificate.Thumbprint)"

            $oids = Parse-CertificateOIDs -Certificate $certificate
            if($oids.AgentId)
            {
                # Extract agent and tenant IDs
                $agentId  = $oids.AgentId
                $tenantId = [guid] $certificate.Subject.Split("=")[1]

                Write-Verbose " Tenant Id: $tenantId, Agent Id: $agentId"

                # Get the certificate
                $binCert = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

                $paths = @(
                    "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys"
                    "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys"
                    "$env:windir\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-20"
                    )

                # Get the correct key name
                if($PTACert)
                {
                    # If stored in NETWORK SERVICE store, PTA Agent's key name can't be readed from the certificate
                    $privateKey = Find-PrivateKey -KeyName $PTAKeyName -Paths $paths -Elevate
                }
                elseif($ProvCert)
                {
                    # If stored in NETWORK SERVICE store, Provisioning Agent's key name can't be readed from the certificate
                    $privateKey = Find-PrivateKey -KeyName $ProvKeyName -Paths $paths -Elevate
                }
                else
                {
                    # Read the key file name from the certificate
                    $fileName = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate).key.uniquename
                    $privateKey = Find-PrivateKey -FileName $fileName -Paths $paths -Elevate
                }

                # Save to pfx file
                $machineName = Get-ComputerName -FQDN
                $fileName = "$($machineName)_$($tenantId)_$($agentId)_$($certificate.Thumbprint).pfx"
                Set-BinaryContent -Path $fileName -Value (New-PfxFile -RSAParameters ($privateKey.RSAParameters) -X509Certificate $binCert)

                # Set the modified date
                (Get-Item -Path $fileName).LastWriteTime = $certificate.NotBefore

                Write-Host "Certificate saved to: $fileName"
            }
        }

    }
}
