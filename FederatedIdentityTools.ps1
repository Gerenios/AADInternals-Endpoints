# Gets immutable id from AD user
function Get-ImmutableID
{
<#
    .SYNOPSIS
    Gets Immutable ID using user's AD object

    .DESCRIPTION
    Gets Immutable ID using user's AD object

    .Parameter ADUser
    Users AD object.

    .Example
    PS C:\>$user=Get-ADUser "myuser"
    PS C:\>$immutableId=Get-AADIntImmutableID -ADUser $user

#>
    [cmdletbinding()]
    Param(
    
        [Parameter(Mandatory=$True)]
        $ADUser
        
    )
    Process
    {
        
        if($ADUser.GetType().ToString() -ne "Microsoft.ActiveDirectory.Management.ADUser")
        {
            Write-Error "ADUser is wrong type. Must be Microsoft.ActiveDirectory.Management.ADUser"
            return
        }

        # Convert GUID to Base64
        $guid=$ADUser.ObjectGUID.ToString()
        $ImmutableId=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.getBytes($guid))

        return $ImmutableId
    }
}