<#
.SYNOPSIS

GroupPolicyMaintenance is a set of PowerShell functions to detect common issues
with overall Group Policy use.

.LINK 

Website: https://github.com/NoMoreFood/Scripts

.HISTORY

1.0.0.0 - Initial Public Release 
1.0.1.0 - Various Console Output Enhancements

.NOTES

Please report any problems or enhancement ideas to the author. If you want to
see continued development of this module please star the article or the GitHub
page under which you found it.

Author: Bryan Berns (Bryan.Berns@gmail.com). 

#>

#Requires -Modules ActiveDirectory
#Requires -Version 3

Set-StrictMode -Version 2.0
Import-Module ActiveDirectory
New-Module -Name 'GroupPolicyMaintenance' -ScriptBlock {

<#
.SYNOPSIS

Gathers information about Group Policy links.

.DESCRIPTION

This function gathers information about Group Policy links in the forest. These
links are in the 'gpLink' attribute on organizational units (OUs); they point to
the Group Policy Objects (GPO) that should be applied when the Group Policy
client reads Active Directory. This function is intended primarily for internal
use by this module, but may be helpful in developing other Group Policy related
functions.

The function assumes the current forest is the forest of interest. It is
recommended that this function be executed with an account that at least has
read permission to all Group Policy objects.

.PARAMETER BrokenLinks

The BrokenLinks switch causes the function to only return information on broken
links. These are links that point to GPOs that either do not exist or cannot be
read. 

.PARAMETER ServerName

Server to use to query Group Policy link and object information from. This
should be a Global Catalog server. If not specified, a local server will be
used.

.PARAMETER Credential

The credentials to query Active Directory. It not specified, the users' current
credentials will be used.

.EXAMPLE

$LinkInfo = Get-GPOLink

#>
Function Get-GPOLink
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [switch] $BrokenLinks,        
        [ValidateNotNull()][string] $ServerName = ([string]::Empty),
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty
    )
    
    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # setup a splat to handle optional credentials
    $OptionalCredentials = @{}
    If ($Credential -ne [PSCredential]::Empty)
    {
        $OptionalCredentials['Credential'] = $Credential
    }

    # find a global catalog to use
    If ([string]::IsNullOrEmpty($ServerName))
    {
        $ServerName = (Get-ADDomainController -Service GlobalCatalog -Discover).HostName[0]
    }

    # add on the global catalog port
    If (-not $ServerName.EndsWith(':3268'))
    {
        $ServerName += ':3268'
    }

    # fetch all objects with links to policies
    $ObjectsWithLinks = @(Get-ADObject -LDAPFilter '(gpLink=*)' `
        -Server $ServerName -Properties gpLink,CanonicalName,DistinguishedName @OptionalCredentials) 

    # fetch all policy object information 
    $PolicyObjects = Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
        -Server $ServerName -Properties DisplayName,Name,Created,CanonicalName,IsDeleted -IncludeDeletedObjects @OptionalCredentials

    # enumerate all link locations
    ForEach ($ObjectWithLinks in $ObjectsWithLinks)
    {
        # extract the list of policies that are attached to the object
        $LinkInfoMatches = $ObjectWithLinks.gpLink | 
            Select-String -Pattern '\[(?<Path>LDAP://.+?);(?<Attributes>\d+)\]' -AllMatches | 
            Select-Object -ExpandProperty Matches

        # each ou/site can have multiple links attached to it
        ForEach ($LinkInfoMatch in $LinkInfoMatches)
        {
            # fetch the general parameters for the link
            $LinkPath = $LinkInfoMatch.Groups['Path'].Value -replace 'LDAP://',''
            $LinkAttributes = $LinkInfoMatch.Groups['Attributes'].Value

            # attempt to get a link to the policy itself for additional
            # parameters
            $PolicyObject = @($PolicyObjects | Where-Object -Property DistinguishedName -EQ -Value $LinkPath)

            # warn about missing object
            $LinkInfo = [ordered]@{}
            $IsBroken = $PolicyObject.Count -eq 0 -or $PolicyObject.IsDeleted
            If ($PolicyObject.Count -eq 0)
            {         
                # process deleted policy with no policy object   
                $LinkInfo['Name'] = ''
                $LinkInfo['Guid'] = [GUID] ($LinkPath -replace '^CN={(.+?-.+?-.+?-.+?-.+?)},.*','{$1}')
                $LinkInfo['Enabled'] = ($LinkAttributes -band 1) -eq 0
                $LinkInfo['Enforced'] = ($LinkAttributes -band 2) -ne 0
                $LinkInfo['PolicyPath'] = $LinkPath
                $LinkInfo['PolicyDomain'] = ''
                $LinkInfo['LinkPath'] = $ObjectWithLinks.DistinguishedName
                $LinkInfo['LinkDomain'] = ($ObjectWithLinks.CanonicalName -split '/')[0]
                $LinkInfo['DeletedRecord'] = $False
            } `
            Else
            {
                # process link information with existing group policy
                $PolicyObject = $PolicyObject[-1]
                $LinkInfo = [ordered]@{}
                $LinkInfo['Name'] = $PolicyObject.DisplayName
                $LinkInfo['Guid'] = [GUID] $PolicyObject.Name
                $LinkInfo['Enabled'] = ($LinkAttributes -band 1) -eq 0
                $LinkInfo['Enforced'] = ($LinkAttributes -band 2) -ne 0
                $LinkInfo['PolicyPath'] = $PolicyObject.DistinguishedName
                $LinkInfo['PolicyDomain'] = ($PolicyObject.CanonicalName -split '/')[0]
                $LinkInfo['LinkPath'] = $ObjectWithLinks.DistinguishedName
                $LinkInfo['LinkDomain'] = ($ObjectWithLinks.CanonicalName -split '/')[0]
                $LinkInfo['DeletedRecord'] = [bool] $PolicyObject.IsDeleted        
            }

            # return object to caller
            If (-not ($BrokenLinks -xor $IsBroken))
            {
                New-Object PSObject -Property $LinkInfo
            }            
        }
    }
}

<#
.SYNOPSIS

Gathers information about Group Policy objects that have been linked across
multiple domains.

.DESCRIPTION

This function gathers information about policies that have been linked across
multiple domains. While cross-linking can be beneficial for management of
multiple domains by a single set of Group Policy Objects (GPOs), it can have
unintended consequences since users or computer that utilize these policies have
to find a foreign domain controller to read them from. If the domain cannot be
contacted or is slow to respond, security may be degraded or performance may be
impacted.

Often times, cross-linking objects is an unintended consequence of using the
Group Policy Management Console (GPMC) since choosing to 'Copy' a GPO in one
domain and then choosing to 'Paste' the GPO in onto an Organization Unit (OU) in
another domain does not result in the Group Policy Object being copied; it will
only be linked to the original domain. This in contrast to choosing to 'Paste'
the GPO into the Group Policy Objects container in GPMC, which actually copies
the GPO to the target domain. Also, since GPMC does not show links from other
domains by default, editing a GPO that has been cross-linked may an unintended
effect other domains if the change was not designed with other domains in mind.
Similarly, an administrator can accidentally delete a cross-linked GPO if the
administrator does not realize the GPO is used in other domains.

.PARAMETER ServerName

Server to use to query Group Policy link and object information from. This
should be a Global Catalog server. If not specified, a local server will be
used.

.PARAMETER Credential

The credentials to query Active Directory. It not specified, the users' current
credentials will be used.

.EXAMPLE

Invoke-GPOCrossLinkedCheck
#>
Function Invoke-GPOCrossLinkedCheck
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [ValidateNotNull()][string] $ServerName = [string]::Empty,
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty
    )
    
    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # warn the user account replication
    Write-Host -ForegroundColor Magenta `
        "NOTICE: This scan uses the Global Catalog. Be mindful of replication delays after changes are made.`r`n"
     
    # get all links
    $Links = @(Get-GPOLink -ServerName $ServerName -Credential $Credential)
    
    # screen out non-cross linked
    $CrossLinkedGPOs = $Links | Where-Object { $_.LinkDomain -ne $_.PolicyDomain }
    ForEach ($CrossLinkedGPO in $CrossLinkedGPOs)
    {
        Write-Host ('Group Policy: ' + $CrossLinkedGPO.Name)
        Write-Host (' → Resides in Domain: ' + $CrossLinkedGPO.PolicyDomain)
        Write-Host (' → But Is Linked In: ' + $CrossLinkedGPO.LinkDomain)
        Write-Host (' → Link Location: ' + $CrossLinkedGPO.LinkPath)
        Write-Host ('')
    }

    # notify user if check found no issues
    If ($CrossLinkedGPO.Count -eq 0)
    {
        Write-Host -ForegroundColor Green "No cross-linked objects detected."
    }
}

<#
.SYNOPSIS

Gathers information about Group Policy Objects (GPOs) that are inaccessible.

.DESCRIPTION

This function gathers information on Organizational Units (OUs) that reference
Group Objects (GPOs) that do not appear to exist or cannot be read by the
administrator executing the command. 

When this command reports that a GPO is inaccessible and it does not exist, then
the policy was deleted without being unlinked from all locations. The most
common cause of this is when the Group Policy is cross-linked between domains
although it could occur intra-domain if the user does have the appropriate
permissions or is using a non-standard GPO editor. 

When this command reports that a GPO is inaccessible and it actually exists, it
is probably because the executing user does not permission to read the GPO. By
default, Authenticated Users (which includes computers) have permissions to read
GPOs. The ability to read GPOs by end users and computers is essential for it to
be applied properly. The most common cause for permissions being changed is the
use of Security Filtering which removes the default 'Read' permission. Security
Filtering is a powerful tool that can be used to make GPOs apply to specific
users and/or computers GPOs without needing to move objects to different OUs.
However, a best practice is to restore the read permission to 'Authenticated
Users' using the delegation tab; this will not actually cause the Group Policy
to all apply to all users; the permission to apply the GPO is actually a
separate permission that can viewed/managed using the Advanced button under the
Delegation tab.

When information is available from the Recycle Bin to resolve the original name
of a deleted GPO, it will be indicated. Otherwise, only the GUID is provided
because that is the only data available.

.PARAMETER ServerName

Server to use to query Group Policy link and object information from. This
should be a Global Catalog server. If not specified, a local server will be
used.

.PARAMETER Credential

The credentials to query Active Directory. It not specified, the users' current
credentials will be used.

.EXAMPLE

Invoke-GPOBrokenLinkCheck
#>
Function Invoke-GPOBrokenLinkCheck
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [ValidateNotNull()][string] $ServerName = [string]::Empty,
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty
    )

    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # warn the user account replication
    Write-Host -ForegroundColor Magenta `
        "NOTICE: This scan uses the Global Catalog. Be mindful of replication delays after changes are made.`r`n"
     
    # get all links
    $Links = @(Get-GPOLink -BrokenLinks -ServerName $ServerName -Credential $Credential)
    
    # screen out non-cross linked 
    ForEach ($Link in $Links)
    {
        If ($Link.DeletedRecord)
        {
            Write-Host -ForegroundColor Red ('Broken Link To Group Policy: ' + $Link.Name)
            Write-Host -ForegroundColor Red (' → Resides in Domain: ' + $Link.PolicyDomain)
            Write-Host -ForegroundColor Red (' → But Is Linked In: ' + $Link.LinkDomain)
            Write-Host -ForegroundColor Red (' → Link Location: ' + $Link.LinkPath)
            Write-Host -ForegroundColor Red ('')
        }
        Else
        {
            Write-Host -ForegroundColor Red ('Broken Link (Or Inaccessible Group Policy): ' + $Link.Name)
            Write-Host -ForegroundColor Red (' → Linked In: ' + $Link.LinkDomain)
            Write-Host -ForegroundColor Red (' → Linked At: ' + $Link.LinkPath)
            Write-Host -ForegroundColor Red (' → Refers To Policy At: ' + $Link.PolicyPath)
            Write-Host -ForegroundColor Red ('')
        }
    }

    # notify user if check found no issues
    If ($Links.Count -eq 0)
    {
        Write-Host -ForegroundColor Green "No broken links detected."
    }
}

<#
.SYNOPSIS

Gathers information about Group Policy Objects (GPOs) that are unused.

.DESCRIPTION

This function scans the forests for all Group Policy Objects (GPOs) that can be
safely removed. This is done by indexing all links in the forest (since GPOs can
linked across domains) and checking which GPOs actually have links pointing to
them.

To delete unused GPOs, the user can chain this function into Remove-GPO or use
the CommandsFile file to produce a PowerShell script that the user can examine
and alter, as necessary, before execution.

.PARAMETER IncludeDisabled

Specifies that GPOs with link that are disabled should be included in the list
returned from the function. The default is to exclude GPOs that are linked but
disable.

.PARAMETER CommandsFile

Creates a file containing Remove-GPO commands that can be independently executed
by the user at a later time. The file will be overwritten if it already exists.

.PARAMETER DomainName

Filter returns to GPOs from a specific domain in fully qualified format
(domain.com). By default, all domains in the current forest are scanned. Even if
this parameter is used, the entire forest is still scanned to ensure no
cross-links exist.

.PARAMETER ServerName

Server to use to query Group Policy link and object information from. This
should be a Global Catalog server. If not specified, a local server will be
used.

.PARAMETER Credential

The credentials to query Active Directory. It not specified, the users' current
credentials will be used.

.EXAMPLE

Get-GPOUnused

.EXAMPLE

Get-GPOUnused -IncludeDisabled | Format-Table -Auto

.EXAMPLE

Get-GPOUnused -IncludeDisabled | Delete-GPO

.EXAMPLE

Get-GPOUnused -IncludeDisabled -CommandsFile 'C:\Group Policies To Delete.ps1'
#>
Function Get-GPOUnused
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [switch] $IncludeDisabled,
        [ValidateNotNull()][string] $DomainName = [string]::Empty,
        [ValidateNotNull()][string] $CommandsFile = [string]::Empty,
        [ValidateNotNull()][string] $ServerName = [string]::Empty,
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty
    )
    
    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # setup a splat to handle optional credentials
    $OptionalCredentials = @{}
    If ($Credential -ne [PSCredential]::Empty)
    {
        $OptionalCredentials['Credential'] = $Credential
    }

    # validate the file path specified is writable
    If (-not [string]::IsNullOrEmpty($CommandsFile))
    {
        If ((Test-Path -IsValid -LiteralPath $CommandsFile) -eq $False)
        {
            Throw 'File specified for deletion commands is not a valid path.'
        }

        # seed the output file
        '# Created By GroupPolicyMaintenance Module ' | Out-File -LiteralPath $CommandsFile -Force
        '' | Out-File -LiteralPath $CommandsFile -Force -Append
    }

    # find a global catalog to use
    If ([string]::IsNullOrEmpty($ServerName))
    {
        $ServerName = (Get-ADDomainController -Service GlobalCatalog -Discover).HostName[0]
    }  
 
    # add on the global catalog port
    If (-not $ServerName.EndsWith(':3268'))
    {
        $ServerName += ':3268'
    }
      
    # get all links
    $Links = Get-GPOLink -ServerName $ServerName -Credential $Credential

    $PolicyObjects = Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
    -Server $ServerName -Properties DisplayName,Name,Created,CanonicalName @OptionalCredentials

    # fetch all policies sorted by domain and display name
    $PolicyObjects = Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
        -Server $ServerName -Properties DisplayName,Name,Created,CanonicalName @OptionalCredentials `
        | Sort-Object {($_.CanonicalName -split '/')[0]},DisplayName

    # remove disabled links from the list of links if requested
    If ($IncludeDisabled) 
    {
        $Links = $Links | Where-Object -Property Enabled -EQ -Value $True
    }

    # create a list of active guids
    $ActivePolicies = $Links | Select-Object -ExpandProperty Guid

    # loop through all policies, looking for those with no links
    ForEach ($PolicyObject in $PolicyObjects)
    {
        # skip policy if in active list
        If ($ActivePolicies -contains ([GUID] $PolicyObject.Name)) { Continue }
       
        # create object to hold the policy to remove
        $UnusedPolicy = [ordered]@{}
        $UnusedPolicy['DisplayName'] = $PolicyObject.DisplayName
        $UnusedPolicy['Guid'] = ([GUID] $PolicyObject.Name)
        $UnusedPolicy['Domain'] = ($PolicyObject.CanonicalName -split '/')[0]
        $UnusedPolicy['Created'] = $PolicyObject.Created

        # do not output if not part of the domain specified
        If (-not [string]::IsNullOrEmpty($DomainName) -and $DomainName -ne $UnusedPolicy['Domain'])
        {
            Continue
        }

        # output object to caller
        New-Object PSObject -Property $UnusedPolicy

        # output to commands file if requested
        If (-not [string]::IsNullOrEmpty($CommandsFile))
        {
            $DisplayName = $UnusedPolicy['DisplayName']
            $Guid = $UnusedPolicy['Guid']
            $Domain = $UnusedPolicy['Domain']
            $Created = $UnusedPolicy['Created']

            $OutInfo = "# Policy: ${DisplayName} " + "`r`n"
            $OutInfo += "# Created On: ${Created} " + "`r`n"
            $OutInfo += "Remove-GPO -Guid '${Guid}' -Domain '${Domain}'" + "`r`n"
            $OutInfo | Out-File -LiteralPath $CommandsFile -Force -Append
        }
    }
}

<#
.SYNOPSIS

Compares Group Policy Objects (GPOs) in Active Directory against the SysVol file
system information to ensure consistency.

.DESCRIPTION

This function analyzes greats a list of all GUIDs in use by group policy on
compares it again the list of GUIDs located at \\domain\sysvol\domain\policies.
By default, all domains in the current forest are scanned.

If a directory exists is missing under SysVol, then the Group Policy Object
(GPO) does not have any information to apply to systems likely is not having the
intended affect. If a directory exists but a corresponding GPO does not exist
then the directory was likely not properly deleted when the GPO was deleted. In
this case, the directory can likely be removed.

.PARAMETER Domain

Specifies a specific domain to process. By default, all domains in the current
forests are enumerated.

.PARAMETER Credential

The credentials to query Active Directory and enumerate the SysVol share. It not
specified, the users' current credentials will be used.

.EXAMPLE

Invoke-GPOSysVolMismatchCheck

#>
Function Invoke-GPOSysVolMismatchCheck
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [ValidateNotNull()][string] $DomainName = [string]::Empty,
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty
    )

    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # setup a splat to handle optional credentials
    $OptionalCredentials = @{}
    If ($Credential -ne [PSCredential]::Empty)
    {
        $OptionalCredentials['Credential'] = $Credential
    }

    # enumerate each domain in the current forest
    $Domains = @(@((Get-ADForest @OptionalCredentials).Domains) | Sort-Object { $_.Split('.').Count, $_ })
    For ($DomainIndex = 0; $DomainIndex -lt $Domains.Count; $DomainIndex++)
    {
        # skip this domain if not the explicit one requested
        $Domain = $Domains[$DomainIndex]
        If (-not [string]::IsNullOrEmpty($DomainName) -and $DomainName -ne $Domain) { Continue }

        # notify user of progress
        Write-Host -ForegroundColor Cyan "Scanning: $Domain"
        Write-Progress -Activity 'Scanning' -PercentComplete (100.0 * $DomainIndex / $Domains.Count) `
            -Status "Scanning Domain: $Domain"
        
        # fetch all policies in the domain
        $DomainController = (Get-ADDomainController -Domain $Domain -Discover).HostName[0]
        $AdObjects = Get-ADObject -LDAPFilter '(objectClass=groupPolicyContainer)' `
            -Server $DomainController -Properties DisplayName,gPCFileSysPath @OptionalCredentials
        $AdDirectories = [ordered]@{}
        $AdObjects | Sort-Object Name | ForEach-Object { $AdDirectories[$_.gPCFileSysPath] = $_ } 

        # lookup all policies in sysvol for the domain
        $Drive = New-PSDrive -Name 'GPM' -PSProvider FileSystem -Root "\\$Domain\SysVol\$Domain\Policies" -Scope Local @OptionalCredentials
        $SysVolDirectories = Get-ChildItem -Directory -Force -LiteralPath "GPM:" `
            | Where-Object -Property Name -Like '{*-*-*-*}' `
            | Sort-Object Name `
            | Select-Object -ExpandProperty FullName
        $Drive | Remove-PSDrive

        # calculate differences 
        $Differences = @(Compare-Object @($AdDirectories.Keys) @($SysVolDirectories))
        If ($Differences.Count -eq 0)
        {
            Write-Host -ForegroundColor Green "Consistency check passed for $Domain"
            Continue
        }

        # report on differences
        ForEach ($Difference in $Differences)
        {
            If ($Difference.SideIndicator -eq '<=')
            {
                Write-Host -ForegroundColor Yellow ('Directory Missing From SysVol: ' + $Difference.InputObject)
                Write-Host -ForegroundColor Yellow (' → Referenced in: ' + $AdDirectories[$Difference.InputObject].DisplayName)
            }
            Else
            {
                Write-Host -ForegroundColor Yellow ('Unused Directory In SysVol: ' + $Difference.InputObject)
            }
        }
    }
}

<#
.SYNOPSIS

Compares system volume share for consistency between domain controllers.

.DESCRIPTION

This function analyzes all files under the SysVol area and compares it between
domain controllers in the domain. Consistency in SysVol is essential where the
actual policy data is accessed by systems and users. If significant differences
are found, the administrator is advised to check to ensure NTFRS or DFS is
running on both systems. The Windows Event Logs may also note that replication
has been suspected and actions much be take for replication to resume. Small
differences in files could be due to changes that were missed by the replication
monitor and should be investigated on a case-by-case basis.

A nearby domain controller within the Active Directory domain is automatically
selected as the 'baseline' server to which all other domain controllers are
compared again.

.PARAMETER DomainName

Specifies the domain name on which to compare all domain controllers. By the
current domain is processed.

.PARAMETER ShareName

The share on the domain controllers to compare. By default 'SysVol' will be
used. Other allowable values include 'NetLogon' and any other custom replicated
directories that share a common share name on all domain controllers.

.PARAMETER Credential

The credentials to query Active Directory, WMI, and Active Directory and
enumerate the SysVol share. It not specified, the users' current credentials
will be used.

.PARAMETER ScanUsingShares

By default, this scan will use administrative shares on the domain controllers
(usually under \\server\c$\windows\sysvol, for example) to ensure that no
automatic redirection is taking place and that the correct server is being
accessed to ensure an accurate scan. As a result, administrative access to the
system is required and WMI must be remotely accessible. You can use the
ScanUsingShares place to use the \\server\sharename instead.

.EXAMPLE

Invoke-GPOReplicationConsistencyCheck

.EXAMPLE

Invoke-GPOReplicationConsistencyCheck -ShareName 'NetLogon'
#>
Function Invoke-GPOReplicationConsistencyCheck
{
    [CmdletBinding(PositionalBinding=$False)]
    Param
    (
        [ValidateNotNullOrEmpty()][string] $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,
        [ValidateNotNullOrEmpty()][string] $ShareName = 'SysVol',
        [ValidateNotNull()][PSCredential] $Credential = [PSCredential]::Empty,
        [switch] $ScanUsingShares
    )

    # stop immediately if encountering an unhandled error
    $Local:ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

    # setup a splat to handle optional credentials
    $OptionalCredentials = @{}
    If ($Credential -ne [PSCredential]::Empty)
    {
        $OptionalCredentials['Credential'] = $Credential
    }

    # fetch all domain controllers 
    $DomainControllers = Get-ADDomainController -Filter * -Server $DomainName @OptionalCredentials

    # fetch the baseline domain controller data
    $BaselineServerName = Get-ADDomainController -DomainName $DomainName -Discover `
        | Select-Object -ExpandProperty HostName | Select-Object -Index 0

    # fetch the share paths for each domain controller
    $SysLocalPaths = @{}
    ForEach ($DomainController in $DomainControllers)
    {
        If ($ScanUsingShares)
        {
            $SysLocalPaths[$DomainController.HostName] = $ShareName
        }
        Else
        {
            $SysLocalPaths[$DomainController.HostName] = 
                Get-WmiObject -Class Win32_Share -ComputerName $DomainController @OptionalCredentials | `
                Where-Object -Property 'Name' -EQ -Value $ShareName | `
                Select-Object -ExpandProperty 'Path' -ErrorAction SilentlyContinue
        }

        # sanity check
        If ([string]::IsNullOrEmpty($SysLocalPaths[$DomainController.HostName]))
        {
            Throw "Could find information for share '$ShareName' on $($DomainController.HostName)"
        }
    }

    # define a function to get the hash data
    Function Get-GPOReplicationConsistencyCheckHashData($ServerName,$LocalPath)
    {
        $SharePath = Join-Path "\\${ServerName}" ($LocalPath -replace ':','$')        
        $Drive = New-PSDrive -Name 'GPM' -PSProvider FileSystem -Root $SharePath -Scope Local @OptionalCredentials
        $Items = Get-ChildItem -LiteralPath 'GPM:' -Recurse -Force -File | `
            Where-Object -Property FullName -NotLike '*\NtFrs_*\*' | `
            Where-Object -Property FullName -NotLike '*\DfsrPrivate\*' | Select-Object `
            @{Name='Hash';Expression={Get-FileHash -LiteralPath $_.FullName | Select-Object -ExpandProperty Hash}},
            @{Name='Path';Expression={$_.FullName.Replace("${SharePath}\",'').ToLower()}}
        $Drive | Remove-PSDrive
        Return $Items
    }

    # get the baseline comparison data
    Write-Progress -Activity 'Indexing' -PercentComplete 1 -Status "Processing Server: $BaselineServerName"
    $BaselineData = Get-GPOReplicationConsistencyCheckHashData `
        -ServerName $BaselineServerName -LocalPath $SysLocalPaths[$BaselineServerName]
                
    # analyze each domain controller against the baseline
    For ($ServerIndex = 0; $ServerIndex -lt @($SysLocalPaths.Keys).Count; $ServerIndex++)
    {
        # fetch server name from array of servers to check
        $ServerName = @($SysLocalPaths.Keys)[$ServerIndex]

        # skip baseline server
        If ($ServerName -eq $BaselineServerName) { Continue }

        # enumerate files and calculate hashes
        Write-Progress -Activity 'Indexing' -PercentComplete (100.0 * $ServerIndex / @($SysLocalPaths.Keys).Count) `
            -Status "Processing Server: $ServerName"
        $CompareData = Get-GPOReplicationConsistencyCheckHashData `
            -ServerName $ServerName -LocalPath $SysLocalPaths[$ServerName]

        # differences
        $Differences = @(Compare-Object -Property Hash,Path -ReferenceObject @($BaselineData) -DifferenceObject @($CompareData))

        # report do no difference scenario 
        If ($Differences.Count -eq 0)
        {
            Write-Host -ForegroundColor Green "No differences between ${ServerName} and ${BaselineServerName}"
        }

        # enumerate files and display differences
        While ($Differences.Count -gt 0)
        {
            # grab a difference to analyze
            $Difference = $Differences[0]
            $DifferencePath = $Difference.Path
            $SameFileDifferences = @($Differences | Where-Object -Property Path -EQ -Value $DifferencePath)
            
            # formulate the potential paths for reporting
            $FilePathServer = "\\${ServerName}\" + ($SysLocalPaths[$ServerName] -replace ':','$') + "\$DifferencePath"
            $FilePathBaseline = "\\${BaselineServerName}\" + ($SysLocalPaths[$BaselineServerName] -replace ':','$') + "\$DifferencePath"

            # handle files that do not exists on one side
            If ($SameFileDifferences.Count -eq 1)
            {
                If ($Difference.SideIndicator -eq '<=')
                {
                    Write-Host -ForegroundColor Yellow "File only exists on ${BaselineServerName}:"
                    Write-Host "  $FilePathBaseline"
                } `
                Else
                {
                    Write-Host -ForegroundColor Yellow "File only exists on ${ServerName}:"
                    Write-Host "  $FilePathServer"
                }
            } `

            # handle files with changed hashes
            Else
            {
                Write-Host -ForegroundColor Yellow "File data differs between servers:"
                Write-Host "  $FilePathBaseline"
                Write-Host "  $FilePathServer"
            }

            # remove entries from the difference list
            $Differences = @($Differences | Where-Object -Property Path -NE -Value $DifferencePath)
        }
    }
}

Export-ModuleMember -Function 'Get-GPOUnused'
Export-ModuleMember -Function 'Invoke-GPOCrossLinkedCheck'
Export-ModuleMember -Function 'Invoke-GPOSysVolMismatchCheck'
Export-ModuleMember -Function 'Invoke-GPOReplicationConsistencyCheck'
Export-ModuleMember -Function 'Invoke-GPOBrokenLinkCheck'

# end module
} | Out-Null
