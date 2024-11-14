# This script contains functions for handling access tokens
# and some utility functions

# Exports Teams access tokens from the Teams cache
# Sep 26th 2022
function Export-TeamsTokens
{
<#
    .SYNOPSIS
    Exports Teams tokens from the provided Cookie database, or from current user's local database.

    .DESCRIPTION
    Exports Teams tokens from the provided Cookie database, or from current user's local database.
    The Teams Cookies database is SQLite database.

    .PARAMETER CookieDatabase
    Full name of the Teams cookie database. If not provided, uses current user's database.

    .PARAMETER AddToCache
    Adds the tokens to AADInternals token cache

    .PARAMETER CopyToClipboard
    Copies the tokens to clipboard as JSON string

    .EXAMPLE
    PS\:>Export-AADIntTeamsTokens
    User: user@company.com

    Name                           Value                                                     
    ----                           -----                                                     
    office_access_token            eyJ0eXAiOiJKV1QiLCJub25jZSI6InlsUjJWRmp4SWFqeVVqeklZa3R...
    skypetoken_asm                 eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwNiIsIng1dCI6Im9QMWFxQnl...
    authtoken                      eyJ0eXAiOiJKV1QiLCJub25jZSI6InpsUFY2bnRCUDR5NTFLTkNQR2l...
    SSOAUTHCOOKIE                  eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sbHJiaFlzYl9rVnU3VzVSa01...

    .EXAMPLE
    PS\:>Export-AADIntTeamsTokens -CookieDatabase C:\Cookies
    User: user@company.com

    Name                           Value                                                     
    ----                           -----                                                     
    office_access_token            eyJ0eXAiOiJKV1QiLCJub25jZSI6InlsUjJWRmp4SWFqeVVqeklZa3R...
    skypetoken_asm                 eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwNiIsIng1dCI6Im9QMWFxQnl...
    authtoken                      eyJ0eXAiOiJKV1QiLCJub25jZSI6InpsUFY2bnRCUDR5NTFLTkNQR2l...
    SSOAUTHCOOKIE                  eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik5sbHJiaFlzYl9rVnU3VzVSa01...

    .EXAMPLE
    PS\:>Export-AADIntTeamsTokens -AddToCache
    User: user@company.com

    3 access tokens added to cache

    .EXAMPLE
    PS\:>Export-AADIntTeamsTokens -AddToCache -CopyToClipboard
    User: user@company.com

    3 access tokens added to cache
    4 access tokens copied to clipboard

    .EXAMPLE
    PS\:>Export-AADIntTeamsTokens -CopyToClipboard
    User: user@company.com

    4 access tokens copied to clipboard

#>
    [cmdletbinding()]
    Param(
        [switch]$AddToCache,
        [switch]$CopyToClipboard,
        [String]$CookieDatabase
    )
    Begin
    {
    }
    Process
    {
        # Set the path if database was not provided, depends on the OS we are running.
        if([string]::IsNullOrEmpty($CookieDatabase))
        {
            switch([system.environment]::OSversion.Platform)
            {
                ("Linux")
                {
                    $CookieDatabase="~/.config/Microsoft/Microsoft Teams/Cookies"
                    break
                }
                ("Unix")
                {
                    $CookieDatabase="~/Library/Application Support/Microsoft/Teams/Cookies"
                    break
                }
                default # Defaults to Windows
                {
                    $CookieDatabase="$env:APPDATA\Microsoft\Teams\Cookies"
                    break
                }

            }
        }

        # Test whether the cookie database exists
        if(-not (Test-Path $CookieDatabase))
        {
            Throw "The Cookie database does not exist: $CookieDatabase"
        }

        try
        {
            # Parse the database
            Write-Verbose "Loading and parsing database $CookieDataBase"
            $parsedDb = Parse-SQLiteDatabase -Data (Get-BinaryContent -Path $CookieDatabase)

            Write-Verbose "Looking for tokens"
            $access_tokens = [ordered]@{}
            foreach($page in $parsedDb.Pages)
            {
                # Cookies data is stored on Table Leaf
                if($page.PageType -eq "Table Leaf" -and $page.CellsOnPage -gt 0)
                {
                    # Which has exactly 19 columns (the last is empty)
                    if($page.Cells[0].Payload.Count -ge 19)
                    {
                        Write-Verbose "Found Table Leaf page with $($page.CellsOnPage) cells"
                        <# Columns - updated Oct 20th 2022
                         0: creation_utc
                         1: top_frame_site_key
                         2: host_key
                         3: name
                         4: value
                         5: encrypted_value
                         6: path
                         7: expires_utc
                         8: is_secure
                         9: is_httponly
                        10: last_access_utc
                        12: has_expires
                        13: is_persistent
                        14: priority
                        15: encrypted_value
                        16: samesite
                        17: source_scheme
                        18: source_port
                        19: is_same_party
                        #>
                        foreach($cell in $page.Cells)
                        {
                            $name  = $cell.Payload[3]
                            $value = $cell.Payload[4]

                            if($name -like "*token*" -or $name -eq "SSOAUTHCOOKIE")
                            {
                                # Strip the Bearer= and query parameters from the "authToken"
                                if($name -eq "authToken")
                                {
                                    $value = [System.Net.WebUtility]::UrlDecode($value).Split("=")[1].Split("&")[0]
                                    $userName = (Read-AccessToken -AccessToken $value).upn
                                }

                                # Add access tokens to cache as needed
                                if($AddToCache -and $name -ne "skypetoken_asm")
                                {
                                    Add-AccessTokenToCache -AccessToken $value | Out-Null
                                    $cached += 1
                                }
                                $access_tokens[$name] = $value
                            }
                        }
                    }
                }
            }

        
        
            # Print out the username
            Write-Host "User: $userName"

            # Print count cached tokens
            if($AddToCache)
            {
                Write-Host "$cached access tokens added to cache"
            }

            # Copy tokens to clipboard and print the count
            if($CopyToClipboard)
            {
                $access_tokens | ConvertTo-Json | Set-Clipboard
                Write-Host "$($access_tokens.Count) access tokens copied to clipboard"
            }

            # Return
            if(-not $AddToCache -and -not $CopyToClipboard)
            {
                return $access_tokens
            }
        }
        catch
        {
            Throw $_
        }
    }
}

# Exports Azure CLI access tokens from the msal_token_cache.bin cache
# Sep 29th 2022
function Export-AzureCliTokens
{
<#
    .SYNOPSIS
    Exports Azure CLI access tokens from the msal_token_cache.bin cache.

    .DESCRIPTION
    Exports Azure CLI access tokens from the msal_token_cache.bin cache. 
    msal_token_cache.bin is a json file protected with DPAPI in LocalUser context.

    .PARAMETER MSALCache
    Full name of the MSAL token cache. If not provided, uses msal_token_cache.bin from current user's profile under .Azure

    .PARAMETER AddToCache
    Adds the tokens to AADInternals token cache

    .PARAMETER CopyToClipboard
    Copies the tokens to clipboard as JSON string

    .EXAMPLE
    PS\:>Export-AADIntAzureCliTokens
    Users: user@company.com,user2@company.com

    UserName          access_token                                                                  
    --------          ------------                                                                  
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...

    .EXAMPLE
    PS\:>Export-AADIntAzureCliTokens -MSALCache "C:\Users\user\.Azure\msal_token_cache.bin.old"
    Users: user@company.com,user2@company.com

    UserName          access_token                                                                  
    --------          ------------                                                                  
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...

    .EXAMPLE
    PS\:>Export-AADIntAzureCliTokens -AddToCache
    Users: user@company.com,user2@company.com

    4 access tokens added to cache

    .EXAMPLE
    PS\:>Export-AADIntAzureCliTokens -AddToCache -CopyToClipboard
    Users: user@company.com,user2@company.com

    4 access tokens added to cache
    4 access tokens copied to clipboard

    .EXAMPLE
    PS\:>Export-AADIntAzureCliTokens -CopyToClipboard
    Users: user@company.com,user2@company.com

    4 access tokens copied to clipboard
#>
    [cmdletbinding()]
    Param(
        [switch]$AddToCache,
        [switch]$CopyToClipboard,
        [switch]$DPAPI,
        [String]$MSALCache
    )
    Begin
    {
        # Load system.security assembly
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Parses the object definition string
        # Sep 29th 2022
        function Parse-ObjectDefinition
        {
            Param(
                [Parameter(Mandatory=$True)]
                [String]$Definition
            )
            Process
            {
                # Get the array
                $Definition = $Definition.Substring($Definition.IndexOf("@"))

                # Get the string between @{ and }
                $Definition = $Definition.Substring(2,$Definition.Length-3)

                $attributes = [ordered]@{}
                if(-not [string]::IsNullOrEmpty($Definition))
                {
                    # Split to array of name=value pairs
                    $properties = $Definition.Split("; ")

                    # Loop through the properties
                    foreach($property in $properties)
                    {
                        # Split & add to attributes
                        $parts = $property.Split("=")
                        if(-not [string]::IsNullOrEmpty($parts[0]))
                        {
                            $attributes[$parts[0]] = $parts[1]
                        }
                    }
                }

                return New-Object -TypeName psobject -Property $attributes
            }
        }

        # Set the path if database was not provided, depends on the OS we are running.
        if([string]::IsNullOrEmpty($MSALCache))
        {
            switch([system.environment]::OSversion.Platform)
            {
                ("Linux")
                {
                    $MSALCache="~/.azure/msal_token_cache.json"
                    break
                }
                ("Unix")
                {
                    $MSALCache="~/.azure/msal_token_cache.json"
                    break
                }
                default # Defaults to Windows
                {
                    $MSALCache="$env:HOMEDRIVE$env:HOMEPATH\.Azure\msal_token_cache.bin"
                    $DPAPI = $true
                    break
                }
            }
        }

        # Test whether the MSAL cache exists
        if(-not (Test-Path $MSALCache))
        {
            Throw "The MSAL token cache does not exist: $MSALCache"
        }

        try
        {
            Write-Verbose "Loading and parsing cache $MSALCache"
            # Unprotect the token cache
            if($DPAPI)
            {
                $decTokens = Get-BinaryContent $MSALCache
                $tokens = [text.encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($decTokens,$null,'CurrentUser'))
            }
            else
            {
                $tokens  = Get-Content $MSALCache -Encoding UTF8
            }

            
            $objTokens = $tokens | ConvertFrom-Json

            $users = [ordered]@{}
            foreach($account in ($objtokens.Account | Get-Member -MemberType NoteProperty))
            {
                # Need to parse the definition manually :(
                $properties = Parse-ObjectDefinition -Definition $account.Definition
                $users[$properties.home_account_id] = $properties.username
            }

            Write-Verbose "Found tokens for $($users.Count) users"


            Write-Verbose "Looking for tokens"
            $access_tokens = @()
            foreach($access_token in ($objtokens.AccessToken | Get-Member -MemberType NoteProperty))
            {
                Write-Verbose "Parsing access token $($access_token.name)"
                # Need to parse the definition manually :(
                $at_properties = Parse-ObjectDefinition -Definition $access_token.Definition

                # Get the refresh token and parse properties if found
                $rt_properties = $null
                $tenantId = $at_properties.home_account_id.Split(".")[1]
                $rt_name = $access_token.name.Replace("accesstoken","refreshtoken").Replace("-organizations-","--").Replace("-$tenantId-","--")
                $refresh_token = $objtokens.RefreshToken | Get-Member -Name $rt_name

                if($refresh_token)
                {
                    Write-Verbose "Parsing refresh token $rt_name"
                    $rt_properties = Parse-ObjectDefinition -Definition $refresh_token.Definition
                }

                # Form the return object
                $attributes = [ordered]@{
                    "UserName"      = $users[$at_properties.home_account_id]
                    "access_token"  = $at_properties.secret
                    "refresh_token" = $rt_properties.secret
                }
                
                if($AddToCache)
                {
                    Add-AccessTokenToCache -AccessToken $at_properties.secret -RefreshToken $rt_properties.secret | Out-Null
                }
                $access_tokens += New-Object psobject -Property $attributes
            }

            # Print out the usernames
            Write-Host "Users: $($users.Values -Join ",")"

            # Print count cached tokens
            if($AddToCache)
            {
                Write-Host "$($access_tokens.Count) access tokens added to cache."
                Write-Host "Note: AADInternals only stores tokens for one user! The token of last added user is used."
            }

            # Copy tokens to clipboard and print the count
            if($CopyToClipboard)
            {
                $access_tokens | ConvertTo-Json | Set-Clipboard
                Write-Host "$($access_tokens.Count) access tokens copied to clipboard"
            }

            # Return
            if(-not $AddToCache -and -not $CopyToClipboard)
            {
                return $access_tokens
            }
        }
        catch
        {
            Throw $_
        }
    }
}

# Exports access tokens from the Token Broker cache
# Oct 20th 2022
function Export-TokenBrokerTokens
{
<#
    .SYNOPSIS
    Exports access tokens from the Token Broker cache.

    .DESCRIPTION
    Exports access tokens from the Token Broker cache. 

    .PARAMETER AddToCache
    Adds the tokens to AADInternals token cache

    .PARAMETER CopyToClipboard
    Copies the tokens to clipboard as JSON string

    .EXAMPLE
    PS\:>Export-AADIntTokenBrokerTokens
    Users: user@company.com,user2@company.com

    UserName          access_token                                                                  
    --------          ------------                                                                  
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user@company.com  eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...
    user2@company.com eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGx...

    .EXAMPLE
    PS\:>Export-AADIntTokenBrokerTokens -AddToCache
    Users: user@company.com,user2@company.com

    4 access tokens added to cache

    .EXAMPLE
    PS\:>Export-AADIntTokenBrokerTokens -AddToCache -CopyToClipboard
    Users: user@company.com,user2@company.com

    4 access tokens added to cache
    4 access tokens copied to clipboard

    .EXAMPLE
    PS\:>Export-AADIntTokenBrokerTokens -CopyToClipboard
    Users: user@company.com,user2@company.com

    4 access tokens copied to clipboard
#>
    [cmdletbinding()]
    Param(
        [switch]$AddToCache,
        [switch]$CopyToClipboard
    )
    Begin
    {
        # Load system.security assembly
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Test whether the Token Broker cache exists
        $TBRES = "$env:LOCALAPPDATA\Microsoft\TokenBroker\Cache\*.tbres"
        
        if(-not (Test-Path $TBRES))
        {
            Throw "The Token Broker cache does not exist: $TBRES"
        }

        $access_tokens = @()
        $users = [ordered]@{}

        # Get the cache files
        $files = Get-Item -Path $TBRES
        foreach($file in $files)
        {
            try
            {
                Write-Verbose "Parsing $file"
                $data    = Get-BinaryContent -Path $file.FullName
                $content = Parse-TBRES -Data $data

                if($content.WTRes_Token -ne $null -and $content.WTRes_Token -ne "No Token")
                {
                    $parsedToken = Read-AccessToken -AccessToken $content.WTRes_Token
                
                    # Could be JWE which can't be parsed
                    if($parsedToken)
                    {
                        $users[$parsedToken.oid] = $parsedToken.unique_name

                        # Form the return object
                        $attributes = [ordered]@{
                            "UserName"      = $parsedToken.unique_name
                            "access_token"  = $content.WTRes_Token
                        }
                
                        if($AddToCache)
                        {
                            Add-AccessTokenToCache -AccessToken $content.WTRes_Token | Out-Null
                        }
                        $access_tokens += [PSCustomObject] $attributes
                    }
                }
            }
            catch
            {
                Write-Verbose "Got exception: $_"
            }

        }
        
        Write-Verbose "Found tokens for $($users.Count) users"

        # Print out the usernames
        if($users.Count -gt 0)
        {
            Write-Host "Users: $($users.Values -Join ",")"
        }
        else
        {
            Write-Host "No tokens found."
        }

        # Print count cached tokens
        if($AddToCache)
        {
            Write-Host "$($access_tokens.Count) access tokens added to cache."
            Write-Host "Note: AADInternals only stores tokens for one user! The token of last added user is used."
        }

        # Copy tokens to clipboard and print the count
        if($CopyToClipboard)
        {
            $access_tokens | ConvertTo-Json | Set-Clipboard
            Write-Host "$($access_tokens.Count) access tokens copied to clipboard"
        }

        # Return
        if(-not $AddToCache -and -not $CopyToClipboard)
        {
            return $access_tokens
        }
    }
}
