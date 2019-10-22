<#
.SYNOPSIS

KerberosDelegationHelper is a set of PowerShell functions ease the 
setup and management of setting up Resource-Based Constrained Kerberos 
delegation.

.HISTORY

1.0.0.0 - Initial Public Release 
1.0.0.1 - Fixed Clear-ADAllowedToActAccount For Computer Objects
1.1.0.0 - Handle case where FrontEndAccount is not in Active Directory

.NOTES

Author: Bryan Berns (Bryan.Berns@gmail.com).  

#>

#Requires -Version 3
Set-StrictMode -Version 2.0
$Script:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

Import-Module ActiveDirectory

<#
.SYNOPSIS

This function adds or removes an account to the list of accounts that an account 
is allowed to act on behalf of. These are stored in the Active Directory 
attribute called msDS-AllowedToActOnBehalfOfOtherIdentity.  This functioned is 
aliased by Add-ADAllowedToActAccount and Remove-ADAllowedToActAccount 
(implies -RemoveAccount).

.PARAMETER FrontEndAccount

The -FrontEndAccount parameter specifies the account from which the delegation
request originates. For example, a the user connects to a frontend web server
and you wish that web server, acting as the user, to be able communicate with
a backend database server. In this scenario, -FrontEndAccount will be the 
computer or service account hosting the web server process.  This account will
not be altered by running this command; it will only be referenced in order to
update the account specified by -BackEndAccount.  

This account can be an object returned from Get-ADComputer or Get-ADUser. It
can also be a string in the form of 'DOMAIN\SamAccountName', 
UserPrincipalName@domain.com, a SID, or an service principal name 
(e.g., HTTP/webserver.domain.com). This command assumes the user executing
the command has write access to the account specified; if this is not the case,
then use the objects returned from the output of the Get-ADUser or 
Get-ADComputer, specifying -Server and -Credential. 

.PARAMETER BackEndAccount

The -BackEndAccount parameter specifies the account hosting the backend service
that the user wishes to access. For example, a the user connects to a frontend 
web server and you wish that web server to connect to a backend database server
acting as the user.  In this scenario -BackEndAccount will be the computer or 
service account hosting the database process.  This account's Active Directory
msDS-AllowedToActOnBehalfOfOtherIdentity attribute will be updated to contain
a reference of the account specified by -FrontEndAccount.

This account can be an object returned from Get-ADComputer or Get-ADUser. It
can also be a string in the form of 'DOMAIN\SamAccountName', 
UserPrincipalName@domain.com, a SID, or an service principal name 
(e.g., MSSQLSvc/sqlsrv.domain.com). This command assumes the user executing
the command has write access to the account specified; if this is not the case,
then use the objects returned from the output of the Get-ADUser or 
Get-ADComputer, specifying -Server and -Credential. 

.PARAMETER RemoveAccount

The default behavior of the command is add the account specified by 
-FrontEndAccount to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of
the account specified by -BackEndAccount.  Use this switch to remove the
entry from the list instead of adding it.  This parameter is implied when 
calling this function using the Remove-ADAllowedToActAccount alias.

.EXAMPLE

Set-ADAllowedToActAccount -FrontEndAccount 'DOMAIN\webacct' -BackEndAccount 'DOMAIN\sqlacct'

.EXAMPLE

$BackEnd = Get-ADComputer 'DOMAIN\webserver'

PS C:\>$FrontEnd = Get-ADComputer 'DOMAIN\sqlserver'

PS C:\>Set-ADAllowedToActAccount -FrontEndAccount $FrontEnd -BackEndAccount $BackEnd

.EXAMPLE

Get-ADUser 'webserver' | Set-ADAllowedToActAccount -BackEndAccount 'DOMAIN\sqlacct'
#>
Function Set-ADAllowedToActAccount
{
    [CmdletBinding()]
    [Alias('Add-ADAllowedToActAccount')]
    [Alias('Remove-ADAllowedToActAccount')]
    Param
    (
        [parameter(ValueFromPipeline,Mandatory)][object] $FrontEndAccount,
        [parameter(Mandatory)][object] $BackEndAccount,
        [switch] $RemoveAccount
    )

    Process
    {
        # automatically set remove if called using remove alias
        If ($MyInvocation.InvocationName -eq 'Remove-ADAllowedToActAccount') 
        {
            $RemoveAccount = $true
        }
        If ($MyInvocation.InvocationName -eq 'Add-ADAllowedToActAccount' -and $RemoveAccount) 
        {
            Throw 'Cannot specify Add-ADAllowedToActAccount with -RemoveAccount'
        }

        # resolve the frontend account to a security identifier
        $FrontEndAccountSid = Resolve-ADAccount -Account $FrontEndAccount -ReturnSid

        # resolve the backend account to an object that can be used with AD cmdlets
        $BackEndAccount = Resolve-ADAccount -Account $BackEndAccount -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        $BackEndAccountList = $BackEndAccount.'msDS-AllowedToActOnBehalfOfOtherIdentity'

        # process removals
        If ($RemoveAccount)
        {
            # nothing to do if list is already empty
            If ($BackEndAccountList -eq $null)
            {
                Throw 'List is already empty; cannot remove the account'
            }

            # remove the entry from the list
            $EntryCount = $BackEndAccountList.Access.Count
            $BackEndAccountList.RemoveAccess($FrontEndAccountSid, `
                ([System.Security.AccessControl.AccessControlType]::Allow))

            # see if the account was removed
            If ($EntryCount -eq $BackEndAccountList.Access.Count)
            {
                Throw 'Account specified could not be found in the list'
            }

            # if new list is empty, just clear it
            If ($BackEndAccountList.Access.Count -eq 0)
            {
                Clear-ADAllowedToActAccount $BackEndAccount
                Return
            }
        } `
        Else
        {
            # construct a new object list if one did not exist        
            If ($BackEndAccountList -eq $null)
            {  
                $BackEndAccountList = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $Owner = New-Object System.Security.Principal.NTAccount 'BUILTIN\Administrators'
                $BackEndAccountList.SetOwner($Owner)  
            }

            # ensure the object is not already in the list
            $AccessEntryCount = $BackEndAccountList.Access.Count
            $BackEndAccountList.RemoveAccess($FrontEndAccountSid, ([System.Security.AccessControl.AccessControlType]::Allow))
            If ($AccessEntryCount -ne $BackEndAccountList.Access.Count)
            {
                Throw 'Account specified is already in the list'
            }
        
            # add the entry to the list
            $NewEntry = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $FrontEndAccountSid, [int] ([DirectoryServices.ActiveDirectoryRights]::GenericAll), 
                ([Security.AccessControl.InheritanceFlags]::None), 
                ([Security.AccessControl.PropagationFlags]::None)) 
            $BackEndAccountList.AddAccessRule($NewEntry)
        }

        # assign the value back to the ad object and commit the data
        $BackEndAccount | Set-ADObject -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$BackEndAccountList}
    }
}

<#
.SYNOPSIS

This function displays all the accounts associated with the specified backend
accounts. It read the msDS-AllowedToActOnBehalfOfOtherIdentity attribute
and returns any entries in the embedded security descriptor

.PARAMETER BackEndAccount

This account can be an object returned from Get-ADComputer or Get-ADUser. It
can also be a string in the form of 'DOMAIN\SamAccountName', a SID, or an 
service principal name (e.g., MSSQLSvc/webserver.domain.com). This command 
assumes the user executing the command has write access to the account 
specified; if this is not the case, then use the objects returned from the 
output of the Get-ADUser or Get-ADComputer, specifying -Server and -Credential. 

.EXAMPLE

Get-ADAllowedToActAccount -BackEndAccount 'DOMAIN\sqlacct'
#>
Function Get-ADAllowedToActAccount
{
    [CmdletBinding()]
    Param
    (
        [parameter(ValueFromPipeline,Mandatory)][object] $BackEndAccount
    )

    Process
    {
        # ensure we have a version of the object with the necessary properties
        $BackEndAccount = Resolve-ADAccount $BackEndAccount -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity'

        # list all the accounts 
        If ($BackEndAccount.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null)
        {
            $BackEndAccount.'msDS-AllowedToActOnBehalfOfOtherIdentity'.Access `
                | Select-Object -ExpandProperty 'IdentityReference' | Select-Object -ExpandProperty 'Value'
        }
    }
}

<#
.SYNOPSIS

This function clears the msDS-AllowedToActOnBehalfOfOtherIdentity from the 
target account.

.PARAMETER BackEndAccount

This account can be an object returned from Get-ADComputer or Get-ADUser. It
can also be a string in the form of 'DOMAIN\SamAccountName', a SID, or an 
service principal name (e.g., MSSQLSvc/webserver.domain.com). This command assumes
the user executing the command has write access to the account specified; if 
this is not the case, then use the objects returned from the output of the 
Get-ADUser or Get-ADComputer, specifying -Server and -Credential. 

.EXAMPLE

Clear-ADAllowedToActAccount -Backend 'DOMAIN\sqlacct'
#>
Function Clear-ADAllowedToActAccount
{
    [CmdletBinding()]
    Param
    (
        [parameter(ValueFromPipeline,Mandatory)][object] $BackEndAccount
    )

    Process
    {
        $BackEndAccount = Resolve-ADAccount $BackEndAccount
        $BackEndAccount | Set-ADObject -Clear @('msDS-AllowedToActOnBehalfOfOtherIdentity')
    }
}

# private function used to resolve active directory accounts
Function Script:Resolve-ADAccount
{
    [CmdletBinding()]
    Param
    (
        [parameter(ValueFromPipeline,Mandatory=$true)] $Account,
        [string[]] $Properties = @('DistinguishedName'),
        [switch] $ReturnSid
    )

    # check if already resolved
    If ($Account -is [Microsoft.ActiveDirectory.Management.ADObject])
    {
        # ensure we have a version of the object with the necessary properties
        If ($ReturnSid) { Return ($Account | Get-ADObject -Properties 'objectSid').objectSid }
        Return $Account | Get-ADObject -Properties $Properties
    }

    # lookup account using spn if string contains a forward slash
    If ($Account -match '/')
    {
        $DomainController = (Get-ADDomainController -Discover -Service GlobalCatalog).HostName
        $Objects = @(Get-ADObject -Filter 'ServicePrincipalName -like $Account' `
            -Server "${DomainController}:3268" -Properties 'objectSID')
        If ($Objects.Count -ne 1)
        {
            Throw "No accounts or duplicate accounts located for SPN: $Account"
        }

        # global catalog based objects cannot be written to so re-resolve
        $AccountSid = $Objects[-1].objectSID
    } `
    ElseIf ($Account -match '^S-1-5-.*')
    {
        $AccountSid = New-Object System.Security.Principal.SecurityIdentifier $Account
    } `
    Else
    {
        # resolve the string to a sid (takes a variable of formats)
        Try
        {
            $AccountGeneric = New-Object System.Security.Principal.NTAccount $Account
            $AccountSid = $AccountGeneric.Translate([System.Security.Principal.SecurityIdentifier])
        }
        Catch
        {
            Throw "Could not resolve account: $Account; Verify the account exists or try another format."
        }
    }

    # if only object sid is requested, return that
    If ($ReturnSid) { Return $AccountSid }

    # resolve the sid to a distinguished name and lookup the bound domain controller
    $AccountAdsi = [ADSI] ('LDAP://<SID=' + $AccountSid.Value + '>')
    $AccountDn = $AccountAdsi.distinguishedName.Value
    $DomainController = $AccountAdsi.PSBase.Options.GetCurrentServerName()
    $AccountAdsi.Close()

    # bind to a adaccount object
    Return Get-ADObject $AccountDn -Server $DomainController -Properties $Properties
}

Export-ModuleMember -Function 'Set-ADAllowedToActAccount' -Alias @('Add-ADAllowedToActAccount','Remove-ADAllowedToActAccount')
Export-ModuleMember -Function 'Get-ADAllowedToActAccount'
Export-ModuleMember -Function 'Clear-ADAllowedToActAccount'
