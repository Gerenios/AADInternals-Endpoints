# This script contains common utility functions used in different functions

# CONSTANTS
$DPAPI_ENTROPY_CNG_KEY_PROPERTIES  = @(0x36,0x6A,0x6E,0x6B,0x64,0x35,0x4A,0x33,0x5A,0x64,0x51,0x44,0x74,0x72,0x73,0x75,0x00) # "6jnkd5J3ZdQDtrsu" + null terminator 
$DPAPI_ENTROPY_CNG_KEY_BLOB		   = @(0x78,0x54,0x35,0x72,0x5A,0x57,0x35,0x71,0x56,0x56,0x62,0x72,0x76,0x70,0x75,0x41,0x00) # "xT5rZW5qVVbrvpuA" + null terminator
$DPAPI_ENTROPY_CAPI_KEY_PROPERTIES = @(0x48,0x6a,0x31,0x64,0x69,0x51,0x36,0x6b,0x70,0x55,0x78,0x37,0x56,0x43,0x34,0x6d,0x00) # "Hj1diQ6kpUx7VC4m" + null terminator

# Gets property value using reflection
# Oct 14 2021
Function Get-ReflectionProperty
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject,
        [parameter(Mandatory=$false)]
        [psobject]$ValueObject,
        [parameter(Mandatory=$true)]
        [String]$PropertyName
    )
    Process
    {
        if(!$ValueObject)
        {
            $ValueObject = $TypeObject
        }

        $propertyInfo = $TypeObject.GetProperty($PropertyName,[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
        return $propertyInfo.GetValue($ValueObject, $null)
    }
}

# Gets property value using reflection
# Oct 14 2021
Function Set-ReflectionProperty
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject,
        [parameter(Mandatory=$false)]
        [psobject]$ValueObject,
        [parameter(Mandatory=$true)]
        [String]$PropertyName,
        [parameter(Mandatory=$true)]
        [psobject]$Value
    )
    Process
    {
        if(!$ValueObject)
        {
            $ValueObject = $TypeObject
        }

        $propertyInfo = $TypeObject.GetProperty($PropertyName,[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
        return $propertyInfo.SetValue($ValueObject, $Value,$null)
    }
}

# Gets object properties using reflection
# Oct 14 2021
Function Get-ReflectionProperties
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject
    )
    Process
    {
        $properties = $TypeObject.GetProperties([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

        foreach($property in $properties)
        {
            New-Object psobject -Property ([ordered]@{
                    "Name"  = $property.Name
                    "Write" = $property.CanWrite
                    "Type"  = $property.PropertyType
                })
        }
    }
}

# Gets field value using reflection
# Feb 24 2022
Function Get-ReflectionField
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject,
        [parameter(Mandatory=$false)]
        [psobject]$ValueObject,
        [parameter(Mandatory=$true)]
        [String]$FieldName
    )
    Process
    {
        if(!$ValueObject)
        {
            $ValueObject = $TypeObject
        }
        $fieldInfo = $TypeObject.GetField($FieldName,[System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
        return $fieldInfo.GetValue($ValueObject)
    }
}

# Gets object properties using reflection
# Feb 24 2022
Function Get-ReflectionFields
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject
    )
    Process
    {
        $fields = $TypeObject.GetFields([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

        foreach($field in $fields)
        {
            New-Object psobject -Property ([ordered]@{
                    "Name"  = $field.Name
                    "Type"  = $field.FieldType
                    "Attributes" = $field.Attributes
                })
        }
    }
}

# Invokes the given method
# Feb 24 2022
Function Invoke-ReflectionMethod
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject,
        [parameter(Mandatory=$False)]
        [psobject]$GenericType,
        [parameter(Mandatory=$False)]
        [psobject]$ValueObject,
        [parameter(Mandatory=$true)]
        [String]$Method,
        [parameter(Mandatory=$False)]
        [Object[]]$Parameters = @()
    )
    Process
    {
        $methodInfo = $TypeObject.GetMethod($Method, [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
        if($methodInfo.IsGenericMethodDefinition)
        {
            $genericMethod = $methodInfo.MakeGenericMethod($GenericType)
            return $genericMethod.Invoke($ValueObject,$Parameters)
        }
        else
        {
            return $methodInfo.Invoke($ValueObject,$Parameters)
        }
    }
}

# Gets object methods using reflection
# Feb 24 2022
Function Get-ReflectionMethods
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [psobject]$TypeObject
    )
    Process
    {
        $methods = $TypeObject.GetMethods([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

        foreach($method in $methods)
        {
            New-Object psobject -Property ([ordered]@{
                    "Name"  = $method.Name
                    "Static" = $method.IsStatic
                    "Attributes" = $method.Attributes
                })
        }
    }
}


# Gets Azure and Azure Stack WireServer ip address using DHCP
# Nov 18 2021
Function Get-AzureWireServerAddress
{
<#
    .SYNOPSIS
    Gets Azure and Azure Stack WireServer ip address using DHCP

    .DESCRIPTION
    Gets Azure and Azure Stack WireServer ip address using DHCP. If DHCP query fails, returns the default address (168.63.129.16)

    .Example
    Get-AADIntAzureWireServerAddress

    168.63.129.16


    
    
#>
    [cmdletbinding()]

    param()
    Begin
    {
    }
    Process
    {
        # Get adapter that are up
        $adapters = Get-NetAdapter | Where AdminStatus -eq "Up" 

        # Loop through the adapters
        foreach($adapter in $adapters)
        {
            # Get IPv4 interfaces that have DHCP enabled
            if((Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).Dhcp -eq "Enabled")
            {
                # Try to query for the address (uses DHCP option 245 and "WindowsAzureGuestAgent" as RequestIdString)
                $ipAddress = [AADInternals.Native]::getWireServerIpAddress($adapter.InterfaceGuid)
            }

            # Return if we found the address
            if($ipAddress)
            {
                return $ipAddress.ToString()
            }
        }
        Write-Warning "WireServer address not found with DHCP, returning default address 168.63.129.16"
        return "168.63.129.16"
    }
}

# Create a new self-signed certificate
# Jan 31st 2021
function New-Certificate
{
<#
    .SYNOPSIS
    Creates a new self signed certificate.

    .DESCRIPTION
    Creates a new self signed certificate for the given subject name and returns it as System.Security.Cryptography.X509Certificates.X509Certificate2 or exports directly to .pfx and .cer files.
    The certificate is valid for 100 years.

    .Parameter SubjectName
    The subject name of the certificate, MUST start with CN=

    .Parameter Export
    Export the certificate (PFX and CER) instead of returning the certificate object. The .pfx file does not have a password.
  
    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    PS C:\>$certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) | Set-Content MyCert.pfx -Encoding Byte

    .Example
    PS C:\>$certificate = New-AADIntCertificate -SubjectName "CN=MyCert"

    PS C:\>$certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) | Set-Content MyCert.cer -Encoding Byte

    .Example
    PS C:\>New-AADIntCertificate -SubjectName "CN=MyCert" -Export

    Certificate successfully exported:
      CN=MyCert.pfx
      CN=MyCert.cer
#>
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidatePattern("[c|C][n|N]=.+")] # Must start with CN=
        [String]$SubjectName,
        [Switch]$Export
    )
    Process
    {
        # Create a private key
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)

        # Initialize the Certificate Signing Request object
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($SubjectName, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
        $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($req.PublicKey,$false))

        # Create a self-signed certificate
        $selfSigned = $req.CreateSelfSigned((Get-Date).ToUniversalTime().AddMinutes(-5),(Get-Date).ToUniversalTime().AddYears(100))
        

        # Store the private key to so that it can be exported
        $cspParameters = [System.Security.Cryptography.CspParameters]::new()
        $cspParameters.ProviderName =    "Microsoft Enhanced RSA and AES Cryptographic Provider"
        $cspParameters.ProviderType =    24
        $cspParameters.KeyContainerName ="AADInternals"
            
        # Set the private key
        $privateKey = [System.Security.Cryptography.RSACryptoServiceProvider]::new(2048,$cspParameters)
        $privateKey.ImportParameters($rsa.ExportParameters($true))
        $selfSigned.PrivateKey = $privateKey

        if($Export)
        {
            Set-BinaryContent -Path "$SubjectName.pfx" -Value $selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            Set-BinaryContent -Path "$SubjectName.cer" -Value $selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)

            # Print out information
            Write-Host "Certificate successfully exported:"
            Write-Host "  $SubjectName.pfx"
            Write-Host "  $SubjectName.cer"
        }
        else
        {
            return $selfSigned
        }
    }
}

# Parses the given Cng blob
# Dec 17th 2021
function Parse-CngBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$false)]
        [switch]$Decrypt,
        [Parameter(Mandatory=$false)]
        [switch]$LocalMachine
    )
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Parse the header
        $version =  [System.BitConverter]::ToInt32($Data,0)
        if($version -ne 1)
        {
            Throw "Unsupported version ($Version), expected 1"
        }
        $unknown =  [System.BitConverter]::ToInt32($Data,4)
        $nameLen =  [System.BitConverter]::ToInt32($Data,8)
        $type    =  [System.BitConverter]::ToInt32($Data,12)

        $publicPropertiesLen  = [System.BitConverter]::ToInt32($Data,16)
        $privatePropertiesLen = [System.BitConverter]::ToInt32($Data,20)
        $privateKeyLen        = [System.BitConverter]::ToInt32($Data,24)
        
        $unknownArray = $Data[28..43]
        
        $name = [text.encoding]::Unicode.GetString($Data, 44, $nameLen)

        Write-Debug "Version:                   $version"
        Write-Debug "Unknown:                   $unknown"
        Write-Debug "Name length:               $nameLen"
        Write-Debug "Type:                      $type"
        Write-Debug "Public properties length:  $publicPropertiesLen"
        Write-Debug "Private properties length: $privatePropertiesLen"
        Write-Debug "Private key length:        $privateKeyLen"
        Write-Debug "Unknown array:             $(Convert-ByteArrayToHex -Bytes $unknownArray)"
        Write-Debug "Name:                      $name`n`n"

        Write-Verbose "Parsing Cng key: $name"

        # Set the position
        $p = 44+$nameLen

        # Parse public properties
        $publicProperties = @{}
        $publicPropertiesTotal = 0
        while($publicPropertiesTotal -lt $publicPropertiesLen)
        {
            $pubStructLen         = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $pubStructType        = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $pubStructUnk         = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $pubStructNameLen     = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $pubStructPropertyLen = [System.BitConverter]::ToInt32($Data,$p); $p += 4

            $pubStructName        = [text.encoding]::Unicode.GetString($Data, $p, $pubStructNameLen); $p += $pubStructNameLen
            $pubStructProperty    = $Data[$p..$($p + $pubStructPropertyLen - 1)]; $p += $pubStructPropertyLen

            $publicPropertiesTotal += $pubStructLen

            if([string]::IsNullOrEmpty($pubStructName))
            {
                $pubStructName = "Public Key"
            }
            elseif($pubStructName -eq "Modified")
            {
               $fileTimeUtc =  [System.BitConverter]::ToInt64($pubStructProperty,0)
               Remove-Variable pubStructProperty
               $pubStructProperty = [datetime]::FromFileTimeUtc($fileTimeUtc)
            }

            Write-Debug "Public property struct length: $pubStructLen"
            Write-Debug "Public property struct type:   $pubStructType"
            Write-Debug "Public property unknown:       $pubStructUnk"
            Write-Debug "Public property name length:   $pubStructNameLen"
            Write-Debug "Public property length:        $pubStructPropertyLen"
            Write-Debug "Public property name:          $pubStructName"

            if($pubStructName -eq "Modified")
            {
                Write-Verbose "Modified:        $($pubStructProperty.ToUniversalTime().ToString("s", [cultureinfo]::InvariantCulture))z`n`n"
            }
            else
            {
                Write-Debug "Public property:               $(Convert-ByteArrayToHex -Bytes $pubStructProperty)`n`n"
            }

            $publicProperties[$pubStructName] = $pubStructProperty
        }
        
        # Parse private properties
        $privateProperties = @{}
        $privatePropertiesTotal = 0

        $privatePropertiesBlob = $Data[$p..$($p + $privatePropertiesLen -1)]
        $privateKeyBlob        = $Data[$($p + $privatePropertiesLen)..$($p + $privatePropertiesLen + $privateKeyLen -1)]
        
        $attributes = [ordered]@{
            "Name"          = $name
            "PublicKeyBlob" = $publicProperties["Public Key"]
            "PrivateKeyBlob" = @()
            "RSAParameters" = Parse-KeyBLOB -Key $publicProperties["Public Key"]
        }
        if($Decrypt)
        {
            $dpapiScope = "CurrentUser"
            
            if($LocalMachine)
            {
                if(!(Is-System))
                {
                    Write-Warning "Trying to decrypt LocalMachine DPAPI while not running as SYSTEM!"
                }
                $dpapiScope = "LocalMachine"
            }
            
            # Decrypt the private key properties using DPAPI
            $decPrivateProperties = [Security.Cryptography.ProtectedData]::Unprotect($privatePropertiesBlob, $DPAPI_ENTROPY_CNG_KEY_PROPERTIES, $dpapiScope)
            $attributes["PrivateKeyProperties"] = $decPrivateProperties

            # Decrypt the private key blob using DPAPI
            $decPrivateBlob = [Security.Cryptography.ProtectedData]::Unprotect($privateKeyBlob, $DPAPI_ENTROPY_CNG_KEY_BLOB, $dpapiScope)
            $attributes["PrivateKeyBlob"] = $decPrivateBlob

            # Convert to RSAFULLPRIVATEBLOB to get all parameters
            $fullPrivateBlob = [AADInternals.Native]::convertKey($decPrivateBlob,"RSAPRIVATEBLOB", "RSAFULLPRIVATEBLOB")
            $attributes["FullPrivateKeyBlob"] = $fullPrivateBlob
            $attributes["RSAParameters"] = Parse-KeyBLOB -Key $fullPrivateBlob
            
        }

        return New-Object psobject -Property $attributes
        
    }
}

# Parses the given CAPI blob
# Mar 3th 2022
function Parse-CapiBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data,
        [Parameter(Mandatory=$false)]
        [switch]$Decrypt,
        [Parameter(Mandatory=$false)]
        [switch]$LocalMachine
    )
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    Process
    {
        # Parse the header
        $version =  [System.BitConverter]::ToInt32($Data,0)
        if($version -ne 2)
        {
            Throw "Unsupported version ($Version), expected 2"
        }
        $unk1          = [System.BitConverter]::ToInt32($Data,4)
        $nameLen       = [System.BitConverter]::ToInt32($Data,8)
        $unk2          = [System.BitConverter]::ToInt32($Data,12)
        $unk3          = [System.BitConverter]::ToInt32($Data,16)
        $publicKeyLen  = [System.BitConverter]::ToInt32($Data,20)
        $privateKeyLen = [System.BitConverter]::ToInt32($Data,24)
        $unk4          = [System.BitConverter]::ToInt32($Data,28)
        $unk5          = [System.BitConverter]::ToInt32($Data,32)
        $privatePropertiesLen = [System.BitConverter]::ToInt32($Data,36)

        $name = [text.encoding]::Ascii.GetString($Data, 40, $nameLen-1)

        Write-Verbose "Parsing CAPI key: $name"

        # Set the position
        $p = 40+$nameLen

        $unkArray = $Data[$p..($p + 20 -1)]; $p += 20

        # Public key CAPI blob
        $publicKeyBlob = $Data[$p..$($p + $publicKeyLen - 1)]; $p += $publicKeyLen
        
        # Get the private key and private properties blobs
        $privateKeyBlob        = $Data[$p..$($p + $privateKeyLen -1)] ; $p += $privateKeyLen
        $privatePropertiesBlob = $Data[$p..$($p + $privatePropertiesLen -1)] 

        $attributes = [ordered]@{
            "Name"           = $name
            "PrivateKeyBlob" = @()
            "RSAParameters"  = Parse-CAPIKeyBLOB -Key $publicKeyBlob
        }
        if($Decrypt)
        {
            $dpapiScope = "CurrentUser"
            
            if($LocalMachine)
            {
                $CurrentUser = "{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME
        
                $dpapiScope = "LocalMachine"
                # Elevate to get access to the DPAPI keys
                if([AADInternals.Native]::copyLsassToken())
                {
                    Write-Warning "Running as LOCAL SYSTEM. You MUST restart PowerShell to restore $CurrentUser rights."
                }
                else
                {
                    Write-Error "Could not elevate, unable to decrypt. MUST be run as administrator!"
                    return
                }
            }
            
            # Decrypt the private key properties using DPAPI
            $decPrivateProperties = [Security.Cryptography.ProtectedData]::Unprotect($privatePropertiesBlob, $DPAPI_ENTROPY_CAPI_KEY_PROPERTIES, $dpapiScope)
            $attributes["PrivateKeyProperties"] = $decPrivateProperties

            # Decrypt the private key blob using DPAPI
            $decPrivateBlob = [Security.Cryptography.ProtectedData]::Unprotect($privateKeyBlob, $null, $dpapiScope)
            
            # Parse the CAPI blob
            $attributes["RSAParameters"] = Parse-CAPIKeyBLOB -Key $decPrivateBlob
        }

        return New-Object psobject -Property $attributes
        
    }
}

# Parses the given CAPI Key BLOB and returns RSAParameters
# Mar 8th 2022
Function Parse-CAPIKeyBLOB
{
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$false,ValueFromPipeline)]
        [Byte[]]$Key
    )
    process
    {
        if($Key -eq $null)
        {
            return $null
        }

        $magic    = [text.encoding]::ASCII.GetString($Key[0..3])
        $modlen   = [bitconverter]::ToUInt32($Key,4)
        $bitlen   = [bitconverter]::ToUInt32($Key,8)
        $unknown  = [bitconverter]::ToUInt32($Key,12)
        $publen   = 4

        $headerLen = 4 * [System.Runtime.InteropServices.Marshal]::SizeOf([uint32]::new())

        # Parse RSA1
        $p = $headerLen
        $pubexp  = $Key[($p)..($p + $publen -1)]; $p += $publen
        $modulus = $key[($p)..($p + $modlen -9)]; $p += $modlen
        
        # Parse RSA2 (RSAPRIVATEBLOB)
        if($magic -eq "RSA2") 
        {
            $prime1 =           $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $p += 4
            $prime2 =           $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $p += 4
            $exponent1 =        $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $p += 4
            $exponent2 =        $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $p += 4
            $coefficient =      $key[($p)..($p-1 + $bitlen/16)] ; $p += $bitlen/16
            $p += 4
            $privateExponent =  $key[($p)..($p-1 + $bitlen/8)] 
        }
        
        $attributes=@{
            "D" =        $privateExponent
            "DP" =       $exponent1
            "DQ" =       $exponent2
            "Exponent" = $pubexp
            "InverseQ" = $coefficient
            "Modulus" =  $modulus
            "P" =        $prime1
            "Q"=         $prime2
        }

        # Reverse
        foreach($name in $attributes.Keys)
        {
            if($attributes[$name])
            {
                [Array]::Reverse($attributes[$name])
            }
        }

        [System.Security.Cryptography.RSAParameters]$RSAParameters = New-Object psobject -Property $attributes

        return $RSAParameters
    }
}

# Checks is the current user running as Administrator
# Feb 6th 2022
function Test-LocalAdministrator  
{
    [cmdletbinding()]

    param(
        [parameter(Mandatory=$False)]
        [switch]$Throw,
        [parameter(Mandatory=$False)]
        [switch]$Warn
    )
    Process
    {  
        $isAdmin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

        if(!$isAdmin -and $Warn)
        {
            Write-Warning "The PowerShell session is not elevated, please run as Administrator."
        }
        elseif(!$isAdmin -and $Throw)
        {
            Throw "The PowerShell session is not elevated, please run as Administrator."
        }
        return $isAdmin
    }
}

# Parses the given Cert BLOB and returns the parsed attributes
# Aug 17th 2022
function Parse-CertBlob
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [byte[]]$Data
    )
    
    Process
    {
        function Get-UnicodeString
        {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$true)]
                [byte[]]$Data,
                [Parameter(Mandatory=$true)]
                [int]$p
            )
    
            Process
            {
                $s = $p
                while($Data[$p] -ne 0 -and $Data[$p+1] -eq 0)
                {
                    $p+=2
                }
                $p+=2
                return [System.Text.Encoding]::Unicode.GetString($Data,$s,$p-$s)
            }
        }

        $p = 0;

        $attributes = [psobject]::new()

        while($p -lt $Data.Length)
        {
            $propId   = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $flags    = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $dataLen  = [System.BitConverter]::ToInt32($Data,$p); $p += 4
            $propData = $Data[$p..($p+$dataLen-1)]; $p += $dataLen

            switch($propId)
            {
                # Provider info
                2 {
                    $pp = 0
                    $containerNameOffset = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $providerNameOffset  = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $providerType        = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $providerFlags       = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $providerParam       = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $providerParamOffset = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4
                    $keySpec             = [System.BitConverter]::ToInt32($propData,$pp); $pp += 4

                    $attributes | Add-Member -NotePropertyName "Container" -NotePropertyValue (Get-UnicodeString -Data $propData -p $containerNameOffset)
                    $attributes | Add-Member -NotePropertyName "Provider"  -NotePropertyValue (Get-UnicodeString -Data $propData -p $providerNameOffset)

                    break
                }
                # SHA1
                3 {
                    $attributes | Add-Member -NotePropertyName "SHA1" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # MD5
                4 {
                    $attributes | Add-Member -NotePropertyName "MD5" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # Friendly Name
                10 {
                    $attributes | Add-Member -NotePropertyName "FriendlyName" -NotePropertyValue (Get-UnicodeString -Data $propData -p 0)
                    break
                }
                # Signature hash
                15 {
                    $attributes | Add-Member -NotePropertyName "SignatureHash" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # Key Identifier
                20 {
                    $attributes | Add-Member -NotePropertyName "KeyIdentifier" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # Issuer Public Key MD5
                24 {
                    $attributes | Add-Member -NotePropertyName "IssuerPublicKeyMD5" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # Subject Public Key MD5
                25 {
                    $attributes | Add-Member -NotePropertyName "SubjectPublicKeyMD5" -NotePropertyValue ((Convert-ByteArrayToHex -Bytes $propData).ToUpper())
                    break
                }
                # DER
                32 {
                    $attributes | Add-Member -NotePropertyName "DER" -NotePropertyValue $propData
                    break
                }
                # SmartCardReader
                101 {
                    $attributes | Add-Member -NotePropertyName "SmartCardReader" -NotePropertyValue (Get-UnicodeString -Data $propData -p 0)
                    break
                }
                Default {
                    Write-Verbose "Unknown certificate property ($propId), size ($dataLen)"
                    break
                }
            }

        }

        return $attributes
    }
}

# Jul 24th 2024
# Returns the name of the current user
function Get-CurrentUser
{
    return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

# Jul 24th 2024
# Return true if running as system
function Is-System
{
    (Get-CurrentUser).equals("NT AUTHORITY\SYSTEM")
}

# Jul 24th 2024
# Run the given command as a service as the given user
function Invoke-ScriptAs
{
<#
    .SYNOPSIS
    Invokes the given PS command as the given user.

    .DESCRIPTION
    Invokes the given PS command as the given user by creating and starting a service.

    .PARAMETER Command
    Command to be executed. Must be shorter than 8191 characters!

    .PARAMETER Credentials
    Credentials of the user or service account

    .PARAMETER GMSA
    Name of the MSA or GMSA service account. Must be available (installed) on the local computer.

    .PARAMETER ServiceName
    Name of the service to be created. Defaults to "AADInternals????" where ???? is a four digit random number.

    .Example
    Invoke-AADIntScriptAs -Command "whoami" -GMSA 'CONTOSO\ADSyncMSA55a35$' -Verbose

    VERBOSE: Creating service AADInternals3486
    VERBOSE:  Creating service to be run as Local System
    VERBOSE:  Changing user to CONTOSO\ADSyncMSA55a35$
    VERBOSE:  Setting ServiceAccountManaged property
    VERBOSE:  Starting service AADInternals3486
    VERBOSE:  Creating outbound named pipe AADInternals3486-out
    VERBOSE:  Sending command AADInternals3486-out
    VERBOSE:  Creating inbound named pipe AADInternals3486-in
    VERBOSE:  Waiting for connection
    VERBOSE:  Reading response from AADInternals3486-in
    contoso\adsyncmsa55a35$
    VERBOSE:  Stopping service AADInternals3486
    VERBOSE:  Deleting service AADInternals3486
    VERBOSE:  Deleting service executable C:\Program Files\WindowsPowerShell\Modules\AADinternals-endpoints\0.9.5\AADInternals3486.exe

    .Example

    Invoke-AADIntScriptAs -Command "whoami" -Verbose
    VERBOSE: Creating service AADInternals5749
    VERBOSE:  Creating service to be run as Local System
    VERBOSE:  Starting service AADInternals5749
    VERBOSE:  Creating outbound named pipe AADInternals5749-out
    VERBOSE:  Sending command AADInternals5749-out
    VERBOSE:  Creating inbound named pipe AADInternals5749-in
    VERBOSE:  Waiting for connection
    VERBOSE:  Reading response from AADInternals5749-in
    nt authority\system
    VERBOSE:  Stopping service AADInternals5749
    VERBOSE:  Deleting service AADInternals5749
    VERBOSE:  Deleting service executable C:\Program Files\WindowsPowerShell\Modules\AADinternals-endpoints\0.9.5\AADInternals5749.exe
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$Command,           
        [Parameter(Mandatory=$false)]
        [pscredential]$Credentials,
        [Parameter(Mandatory=$false)]
        [String]$GMSA,
        [Parameter(Mandatory=$false)]
        [String]$ServiceName="AADInternals$(Get-Random -Minimum 1000 -Maximum 9999)"
      )
    Begin
    {

    }
    Process
    {
        if($command.Length -gt 8191)
        {
            Write-Warning "Command length $($command.Length) greater than 8191, execution probably fails!"
        }
        $description = "Service to run PowerShell commands as System or other users"
        
        # Path to service executable.
        $folder = $PSScriptRoot
        if([string]::IsNullOrEmpty($folder))
        {
            $folder = (Get-Location).Path
        }
        $servicePath="$folder\$ServiceName.exe"

        # The service source code
        $serviceSource=@"
using System;
using System.IO.Pipes;
using System.IO;
using System.Reflection;
using System.ServiceProcess;
using System.Threading;
using System.Management;
using System.Diagnostics;
using System.Text;

namespace AADInternals
{
    public class $ServiceName : ServiceBase
    {
        public static void Main() 
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new $ServiceName()
            };
            ServiceBase.Run(ServicesToRun);
        }


        protected override void OnStart(string[] args)
        {
            new Thread(Service).Start();
        }

        private static void Service()
        {
            string command = "";

            //
            // Wait for the command
            //
            using (NamedPipeServerStream pipeServer = new NamedPipeServerStream("$ServiceName-out", PipeDirection.InOut))
            {
                // Wait for a client to connect
                pipeServer.WaitForConnection();

                try
                {
                    // Read the command
                    using (StreamReader sr = new StreamReader(pipeServer))
                    {
                        while (!sr.EndOfStream)
                            command += sr.ReadLine();
                    }

                }
                catch (IOException e){}
            }

            //
            // Run the command
            //
            string returnValue;
            try
            {
                Process p = new Process();
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.StartInfo.FileName = "PowerShell.exe";
				p.StartInfo.Arguments = String.Format("-ExecutionPolicy Bypass -Command \"& {{{0}}}\"", command);
				p.Start();

				// Read the output
				returnValue = p.StandardOutput.ReadToEnd();
				p.WaitForExit();
            }
            catch (Exception e)
            {
                returnValue = e.InnerException.Message.Replace(System.Environment.NewLine, "");
            }

            //
            // Send the response back to client
            //

            using (NamedPipeClientStream pipeClient = new NamedPipeClientStream(".", "$ServiceName-in", PipeDirection.InOut))
            {
                // Connect
                pipeClient.Connect();

                try
                {
                    using (StreamWriter sw = new StreamWriter(pipeClient,Encoding.UTF8,UInt16.MaxValue))
                    {
                        
                        sw.AutoFlush = true;
                        sw.WriteLine(returnValue);
                    }
                }
                catch (IOException e){};
            }
        }
    }
}
"@
        try
        {

            # Create the service executable
            try
            {
                Add-Type -TypeDefinition $serviceSource -Language CSharp -OutputAssembly $servicePath -OutputType ConsoleApplication -ReferencedAssemblies "System.ServiceProcess" -Debug:$false -IgnoreWarnings
            }
            catch
            {
                throw "Unable to create service executable ($servicePath): $($_.Exception.Message)"
            }

            # Create the service
            Write-Verbose "Creating service $ServiceName"

            
            # Group Managed Service Account
            if($GMSA)
            {
                Write-Verbose " Creating service to be run as Local System"
                $service = New-Service -Name $ServiceName -BinaryPathName $servicePath -Description $Description -ErrorAction SilentlyContinue

                # Change the user to provided service account
                Write-Verbose " Changing user to $GMSA"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "ObjectName"            -Value $GMSA

                # Set the account to service account managed - (not required)
                Write-Verbose " Setting ServiceAccountManaged property"
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name "ServiceAccountManaged" -Value ([System.BitConverter]::GetBytes([int32]1)) 
            }
            elseif($Credentials)
            {
                # First, give permissions to service executable
                Write-Verbose " Adding ReadAndExecute permissions to $servicePath for Everyone"
                $permissions = Get-Acl -Path $servicePath -ErrorAction SilentlyContinue

                $accessRule = [Security.AccessControl.FileSystemAccessrule]::new("Everyone", [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.AccessControlType]::Allow)
                $permissions.AddAccessRule($accessRule)
                
                Set-Acl -Path $servicePath -AclObject $permissions -ErrorAction SilentlyContinue

                # Start with provided credentials
                Write-Verbose " Creating service to be run as $($Credentials.UserName) with password $($Credentials.GetNetworkCredential().Password)"
                $service = New-Service -Name $ServiceName -BinaryPathName $servicePath -Description $Description -Credential $credentials -ErrorAction SilentlyContinue
            }
            else
            {
                # Start as Local System
                Write-Verbose " Creating service to be run as Local System"
                $service = New-Service -Name $ServiceName -BinaryPathName $servicePath -Description $Description -ErrorAction SilentlyContinue
            }

            # Start the service
            if($service)
            {
                Write-Verbose " Starting service $ServiceName"
                
                Start-Service -Name $ServiceName -ErrorAction Stop
            }
            else
            {
                Throw "Could not create service $ServiceName"
            }

            # Create an output named piped client to connect to the service
            try 
            {
                Write-Verbose " Creating outbound named pipe $ServiceName-out"
                $pipeOut = [System.IO.Pipes.NamedPipeClientStream]::new(".","$ServiceName-out")
                $pipeOut.Connect(5000) # Timeout 5 seconds

                $sw = [System.IO.StreamWriter]::new($pipeOut)
                $sw.AutoFlush = $true
    
                # Send the configuration to the service
                Write-Verbose " Sending command $ServiceName-out"
                $sw.WriteLine($Command)
            } 
            catch
            {
                Throw "Error send message to service: $_"
            } 
            finally 
            {
                if ($sw) 
                {
                    $sw.Dispose() 
                }
            }
            if ($pipeOut) 
            {
                $pipeOut.Dispose()
            }
        
            # Create an input named piped client to receive output from the service
            try 
            {
                Write-Verbose " Creating inbound named pipe $ServiceName-in"
                # Allow everyone to access the pipe
                $pse = [System.IO.Pipes.PipeSecurity]::new()
                $sid = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
                $par = [System.IO.Pipes.PipeAccessRule]::new($sid, [System.IO.Pipes.PipeAccessRights]::ReadWrite, [System.Security.AccessControl.AccessControlType]::Allow)
                $pse.AddAccessRule($par)
                $pipeIn = [System.IO.Pipes.NamedPipeServerStream]::new("$ServiceName-in",[System.IO.Pipes.PipeDirection]::InOut,1,[System.IO.Pipes.PipeTransmissionMode]::Message, [System.IO.Pipes.PipeOptions]::None,4096,4096,$pse)
            
                Write-Verbose " Waiting for connection"
                $pipeIn.WaitForConnection()

                Write-Verbose " Reading response from $ServiceName-in"
                $sr = [System.IO.StreamReader]::new($pipeIn)
            
                while(!$sr.EndOfStream)
                {
                    $message += $sr.Readline()
                }
            } 
            catch 
            {
                Throw "Error receiving message from service: $_"
            } 
            finally 
            {
                if ($sr) 
                {
                    $sr.Dispose() 
                }
                if ($pipeIn) 
                {
                    $pipeIn.Dispose()
                }
            }

            Write-Debug " Message: $message"
            return $message
        }
        catch
        {
            throw $_
        }
        Finally
        {
            # Clean up
            Remove-Services -ServiceName $ServiceName
        }
    }
}

# Jul 25th 2024
# Finds the private key using a key or file name.
function Find-PrivateKey
{
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = "KeyName",Mandatory=$True)]
        [String]$KeyName,
        [Parameter(ParameterSetName = "FileName",Mandatory=$True)]
        [String]$FileName,
        [Parameter(Mandatory=$False)]
        [switch]$Elevate,
        [Parameter(Mandatory=$False)]
        [switch]$AsJson,
        [Parameter(Mandatory=$False)]
        [string[]]$Paths
    )
    Begin
    {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
    }
    Process
    {
        # Required to run as system?
        if($Elevate -and !(Is-System))
        {
            Write-Verbose "Elevating to LOCAL SYSTEM."
            $cmdToRun = "Set-Location '$PSScriptRoot';. '.\Win32Ntv.ps1';. '.\CommonUtils.ps1'; Find-PrivateKey -Elevate -AsJson"
            if($KeyName)
            {
                $cmdToRun += " -KeyName '$KeyName'"
            }
            else
            {
                $cmdToRun += " -FileName '$FileName'"
            }

            if($Paths)
            {
                $cmdToRun += " -Paths '$($Paths -join "','")'"
            }

            Write-Verbose "Command = $cmdTorun"
                
            try
            {
                $keyJson = Invoke-ScriptAs -Command $cmdToRun
                $key = ConvertFrom-Json -InputObject $keyJson

                # Re-create RSAParameters
                $rsaParameters = [System.Security.Cryptography.RSAParameters]$key.rsaparameters
                $key.PSObject.Properties.Remove("RSAParameters")
                $key | Add-Member -NotePropertyName "RSAParameters" -NotePropertyValue $rsaParameters

                return $key
            }
            catch
            {
                throw "Unable to get private key as LOCAL SYSTEM"
            }
        }

        # Get the key blob
        if($Elevate)
        {
            $keyPath = "$env:ALLUSERSPROFILE"
        }
        else
        {
            $keyPath = "$env:APPDATA"
        }

        # CryptoAPI and CNG stores keys in different directories
        # https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
        if(!$Paths)
        {
            $paths = @(
                "$keyPath\Microsoft\Crypto\RSA\MachineKeys"
                "$keyPath\Microsoft\Crypto\Keys"
                "$keyPath\Microsoft\Crypto\SystemKeys"
                "$keyPath\Application Data\Microsoft\Crypto\Keys"
                "$env:windir\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-20\"
                )
        }    
        # Loop through the paths
        foreach($path in $paths)
        {
            # If path exists..
            if(Test-Path -Path $path)
            {
                Write-Verbose "Processing $path"
                # If filename provided, try to open the file
                if($FileName)
                {
                    if(Test-Path -Path "$path\$FileName")
                    {
                        Write-Verbose "Key for file name $FileName found!"
                        $keyBlob = Get-BinaryContent -Path "$path\$FileName"
                        break
                    }
                }
                else 
                {
                    # Open each file until matching key is found
                    $keyFiles = Get-ChildItem -Path $path
                    foreach($keyFile in $keyFiles)
                    {
                        $keyBlob = Get-BinaryContent -Path $keyFile.FullName

                        # Parse the blob to get the name
                        $blobType = [System.BitConverter]::ToInt32($keyBlob,0)
                        switch($blobType)
                        {
                            1 { $key = Parse-CngBlob  -Data $keyBlob }
                            2 { $key = Parse-CapiBlob -Data $keyBlob }
                            default { throw "Unsupported key blob type" }
                        }
                                                        
                        if($key.name -eq $transPortKeyName)
                        {
                            Write-Verbose "Key for name $KeyName found!"
                            break
                        }
                    }
                }
            }
        }

        # Decrypt the blob
        if($keyBlob)
        {
            # Parse the key blob
            $blobType = [System.BitConverter]::ToInt32($keyBlob,0)
            switch($blobType)
            {
                1 { $key = Parse-CngBlob  -Data $keyBlob -Decrypt }
                2 { $key = Parse-CapiBlob -Data $keyBlob -Decrypt }
                default { throw "Unsupported key blob type" }
            }

            if($AsJson)
            {
                return (ConvertTo-Json -InputObject $key -Compress)
            }
            else
            {
                return $key
            }
        }
        else
        {
            if($AsJson)
            {
                return $null
            }
            else
            {
                throw "Key not found!"
            }
        }
            
    }

}


# Nov 5th 2024
# Remove the given or all AADInternals services used by Invoke-ScriptAs
function Remove-Services
{
<#
    .SYNOPSIS
    Removes the given or all AADInternalsXXXX services created by Invoke-AADIntScriptAs

    .DESCRIPTION
    Removes the given or all AADInternalsXXXX services created by Invoke-AADIntScriptAs. 
    If the invoke fails, service and service executable may remain on the disk.

    .PARAMETER ServiceName
    Name of the service to be removed

    .Example
    Remove-AADIntServices -Verbose

    VERBOSE:  Removing all AADInternals services
    VERBOSE:  Stopping service AADInternals1522
    VERBOSE:  Deleting service AADInternals1522
    VERBOSE:  Deleting service executable C:\Program Files\WindowsPowerShell\Modules\AADinternals-endpoints\0.9.5\AADInternals1522.exe
    VERBOSE:  Deleting service executable C:\Program Files\WindowsPowerShell\Modules\AADinternals-endpoints\0.9.5\AADInternals3279.exe
    VERBOSE:  Deleting service executable C:\Program Files\WindowsPowerShell\Modules\AADinternals-endpoints\0.9.5\AADInternals4934.exe
#>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$ServiceName
      )
    
    Process
    {
        # Path to service executable.
        $folder = $PSScriptRoot
        if([string]::IsNullOrEmpty($folder))
        {
            $folder = (Get-Location).Path
        }

        $servicePaths=@()

        if([string]::IsNullOrEmpty($ServiceName))
        {
            Write-Verbose " Removing all AADInternals services"
            foreach($servicePath in Get-ChildItem -Path $folder -Filter "AADInternals????.exe")
            {
                $servicePaths += $servicePath.FullName
            }
        }
        else
        {
            $servicePaths += "$folder\$ServiceName.exe"
        }
        
        foreach($servicePath in $servicePaths)
        {
            $ServiceName = (Get-ChildItem -Path $servicePath).PSChildName.Split(".")[0]

            if(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
            {
                Write-Verbose " Stopping service $ServiceName"
                Stop-Service $ServiceName -ErrorAction SilentlyContinue | Out-Null
                Write-Verbose " Deleting service $ServiceName"
                SC.exe DELETE $ServiceName | Out-Null
            }

            Write-Verbose " Deleting service executable $servicePath"
            Remove-Item -Path $servicePath -Force -ErrorAction SilentlyContinue

        }
    }
}