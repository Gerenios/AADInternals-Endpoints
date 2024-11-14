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
