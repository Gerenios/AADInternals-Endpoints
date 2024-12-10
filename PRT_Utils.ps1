# Parses the Cloud AP Cache Data CacheData
# C:\Windows\system32\config\systemprofile\AppData\local\microsoft\windows\CloudAPCache\AzureAD\<hash>\cache\cachedata
# May 31st 2023
function Parse-CloudAPCacheData
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        if($version -ne 2)
        {
            Throw "Invalid version: $version. Was expecting 2."
        }

        $hash    =  $Data[($p)..($p-1 + 32)];                 $p += 32
        $p       += 8
        $dataLen =  [System.BitConverter]::ToInt64($Data,$p); $p += 8

        Write-Verbose "CacheData version:      $version"
        Write-Verbose "CacheData SHA256:       $(Convert-ByteArrayToHex -Bytes $hash)"
        Write-Verbose "CacheData length:       $dataLen"

        $unk =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        
        $keyId = [guid][byte[]]$Data[($p)..($p-1 + 16)];     $p += 16
        Write-Verbose "CacheData key id:       $keyId"

        # Number of nodes
        $nodes =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        # 00 00 02 00
        $unk2 =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        # Number of nodes (again)
        $nodes =  [System.BitConverter]::ToInt32($Data,$p); $p += 4

        $cacheNodes = [array]::CreateInstance([pscustomobject],$nodes)

        Write-Verbose "$nodes nodes"
        for($n = 0 ; $n -lt $nodes; $n++)
        {
            $type = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            Write-Verbose "Node $($n+1) type:      $type"

            $cryptoBlobSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            Write-Verbose " CryptoBlob length:     $cryptoBlobSize"
            # 04 00 02 00
            $unk3 =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $encryptedBlobSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            Write-Verbose " EncryptedBlob length:  $encryptedBlobSize"
            # 08 00 02 00
            $unk4 =  [System.BitConverter]::ToInt32($Data,$p); $p += 4

            $cacheNodes[$n] = [pscustomobject][ordered]@{
                "Type"              = $type
                "CryptoBlobSize"    = $cryptoBlobSize
                "EncryptedBlobSize" = $encryptedBlobSize
                "CryptoBlob"        = New-Object byte[] $cryptoBlobSize
                "EncryptedBlob"     = New-Object byte[] $encryptedBlobSize
            }
        }

        foreach($cacheNode in $cacheNodes)
        {
            $cryptoBlobSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            Write-Verbose "CryptoBlobSize:    $cryptoBlobSize"
            $cacheNode.CryptoBlob     = $Data[($p)..($p-1 + $cryptoBlobSize)];        $p += $cryptoBlobSize

            if($p % 4 -ne 0)
            {
                $p += (4 - ($p % 4))
            }

            $encryptedBlobSize = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            Write-Verbose "EncryptedBlobSize length:   $encryptedBlobSize"
            $cacheNode.EncryptedBlob     = $Data[($p)..($p-1 + $encryptedBlobSize)];       $p += $encryptedBlobSize

            if($p % 4 -ne 0)
            {
                $p += (4 - ($p % 4))
            }
        }


        return $cacheNodes
     }
}

# Parses the decrypted data blob from CacheData
# Jun 2nd 2023
function Parse-CloudAPEncryptedBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        if($version -ne 0)
        {
            Throw "Invalid version: $version. Was expecting 0."
        }

        $unk01   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk02   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk03   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk04   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk05   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk06   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $unk07   =  [System.BitConverter]::ToInt32($Data,$p); $p += 4

        $keyId   =  [guid][byte[]]$Data[($p)..($p-1 + 16)];   $p += 16
        $id1     =  $Data[($p)..($p-1 + 32)];                 $p += 32
        $id2     =  $Data[($p)..($p-1 + 32)];                 $p += 32

        Write-Verbose "CacheData blob version: $version"
        Write-Verbose "CacheData key id:       $keyId"
        Write-Verbose "CacheData blob ID1?:    $(Convert-ByteArrayToHex -Bytes $id1)"
        Write-Verbose "CacheData blob ID2?:    $(Convert-ByteArrayToHex -Bytes $id2)"
        
        # Return the payload
        return $Data[$p..$($Data.Length)]
     }
}

# Decrypts POP Key (Session Key) blob using DPAPI
# May 31st 2023
function Unprotect-POPKeyBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    Begin
    {
        # Load system.security assembly
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Parse the header
        $p = 0;
        $version =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        $type    =  [System.BitConverter]::ToInt32($Data,$p); $p += 4
        Write-Verbose "SessionKey version: $version"
        Write-Verbose "SessionKey type:    $type"
        if($type -ne 1)
        {
            Throw "Only software key (type 1) can be exported."
        }

        # Get the key
        $key = $Data[$p..$($Data.Count)]
        
        # Decrypt using DPAPI
        return [Security.Cryptography.ProtectedData]::Unprotect($key,$null,'LocalMachine')
     }
}
