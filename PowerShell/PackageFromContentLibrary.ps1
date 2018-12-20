<#
.SYNOPSIS

PackageFromContentLibrary is a set of PowerShell functions that allow an 
administrator to extract the original source directory from the content
library. 

.HISTORY

1.0.0.0 - Initial Public Release 

.NOTES

This script does not require the CM PowerShell cmdlets to be installed or 
loaded in order to execute.

This script can be imported into your PowerShell session or it can be
executed form the command line using the following syntax:

PowerShell -File PackageFromContentLibrary.ps1 -ContentServer <Server>
  -PackageId <PackageId>

Author: Bryan Berns (Bryan.Berns@gmail.com).  

#>

#Requires -Version 3
Set-StrictMode -Version 2.0
New-Module -Name PackageFromContentLibrary -ScriptBlock {

<#
.SYNOPSIS

This is an internal function to fetch the INI content of a file and return it 
as as a hash of hashes.
#>
Function Script:Get-CMIniContentPath() 
{  
    # define function parameters
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)] $Path
    )

    # the file is processed from top to bottom and any name=value pairs found
    # are assumed to associated with the last [Section] found so this tracks
    # the most recently seen [Section]
    $ActiveSection = ''

    # this is the hash of hashes of the parsed content.  By default, we 
    # populate an empty element that will pick up any value pairs that are
    # matched prior to the first section being found. 
    $Data = [ordered]@{''=@{}}
     
    Switch -Regex -File $Path  
    {  
        # comment - any line beginning with ';'
        '^\s*;'
        {
            # Ignore
        } 

        # section - any line matching '[Section]'
        '^\s*\[(.+?)\]\s*$' 
        {  
            $ActiveSection = $Matches[1]
            $Data[$ActiveSection] = @{}
        }  

        # value Data - any line matching 'Name=Value'
        '^\s*([^=]+?)\s*=\s*(.*?)\s*$'  
        {  
            $Data[$ActiveSection][$Matches[1]] = $Matches[2]  
        }  
    }  

    # remove any data not under section
    $Data.Remove('')

    # return hash table
    Return $Data    
}  

<#
.SYNOPSIS

This is an internal function to translate a list of WMI named parameters to 
ordered parameters since the built-in WMI functions do not support named
parameters.

#>
Function Script:Get-WmiOrderedListFromNamedArguments
{
    # define function parameters
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)][hashtable]$NamedArguments, 
        [Parameter(Mandatory)][string]$ComputerName, 
        [Parameter(Mandatory)][string]$Namespace, 
        [Parameter(Mandatory)][string]$Class, 
        [Parameter(Mandatory)][string]$Method
    )

    $ArgumentList = @()
    $ClassInfo = New-Object System.Management.ManagementClass -ArgumentList "\\${ComputerName}\${NameSpace}:${Class}"
    ForEach ($Argument in $ClassInfo.GetMethodParameters($Method).Properties)
    {
        $ArgumentList += $NamedArguments[$Argument.Name]
    }
    Return $ArgumentList
}

<#
.SYNOPSIS

This is an internal function to fetch the valid content library location on a
content server.
#>
Function Script:Get-CMFileLibPaths([string] $ContentServer)
{
    # lookup the distribution point key on the remote machine to determine where the
    # various files for the content library can be
    $RootKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey( `
        [Microsoft.Win32.RegistryHive]::LocalMachine, $ContentServer)
    $SubKey = $RootKey.OpenSubKey('Software\Microsoft\SMS\DP')
    $Drives = $SubKey.GetValue('ContentLibUsableDrives') -split ','
    $ContentLibraryPath = $SubKey.GetValue('ContentLibraryPath') 
    $SubKey.Close()
    $RootKey.Close()
    
    # construct the path for the main content library file location 
    $ContentLibPaths = @(
        [System.IO.Path]::Combine("\\$ContentServer", $ContentLibraryPath.Replace(':','$'), 'FileLib'))

    # enumerate the usable drives, looking for valid paths to add
    ForEach ($Drive in $Drives)
    {
        # construct the potential content lib path
        $PotentialPath = [System.IO.Path]::Combine("\\$ContentServer", $Drive.Replace(':','$'), 'SCCMContentLib\FileLib')
        If ($ContentLibPaths -notcontains $PotentialPath -and (Test-Path $PotentialPath))
        {
            $ContentLibPaths += $PotentialPath
        }
    }

    # return any discovered entries
    Return $ContentLibPaths
}

<#
.SYNOPSIS

This function calculates an overall hash for a directory structure.

.PARAMETER Path

The -Path specifies the directory to hash.

.NOTES

This algorithm appears to be proprietary and publicly undocumented.  
It could change in future revision of SCCM.

The process used to calculate this hash uses SHA256 hashes but CM appears to
have the flexibility to adapt to other types of hashes.  If another type of
hash appears to be used in new SCCM revision, this function could be updated
to accommodate it.

.EXAMPLE

Get-CMDirectoryHash -Path 'V:\MyPackage' 
#>
Function Global:Get-CMDirectoryHash
{
    # define function parameters
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)][string] $Path
    )

    # normalize the end of the path
    $Path = $Path.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $Path += [System.IO.Path]::DirectorySeparatorChar

    # get an directory item in order to normalize the path 
    $ItemToHash = (Get-Item -LiteralPath $Path)

    # determine the amount of character we need to trim from full names to make
    # paths relative to the root directory
    $Path = $ItemToHash.FullName
    $AmountToTrim =  $ItemToHash.FullName.Length

    # create a cryptographic hashing stream to feed our data into
    $MemoryStream = New-Object System.IO.MemoryStream
    $Alg = New-Object System.Security.Cryptography.SHA256Managed
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`
        $MemoryStream, $Alg,[System.Security.Cryptography.CryptoStreamMode]::Write)

    # process the output directory in a stack (i.e. equivalent to recursively
    # descending into the structure)
    $DirectoryStack = New-Object System.Collections.Stack
    $DirectoryStack.Push($ItemToHash)
    While ($DirectoryStack.Count -gt 0)
    {
        $Directory = $DirectoryStack.Pop()

        # encode the relative paths of the subdirectories for this parent directory
        $SubDirectories = @(Get-ChildItem -Force -LiteralPath $Directory.FullName -Directory)
        ForEach ($SubDirectory in $SubDirectories)
        {
            $ToWrite = $SubDirectory.FullName.Substring($AmountToTrim).ToLower()
            $Data = [System.Text.Encoding]::Unicode.GetBytes($ToWrite)
            $CryptoStream.Write($Data, 0, $Data.Length)
        }

        # push the subdirectories onto the stack in reverse order so the first
        # alphabetically with be the first to be processed
        ForEach ($SubDirectory in ($SubDirectories | Sort-Object -Descending))
        {
            $DirectoryStack.Push($SubDirectory)
        }
        
        # encode the relative paths for all files in this parent directory
        $Files = @(Get-ChildItem -Force -LiteralPath $Directory.FullName -File)
        ForEach ($File in $Files)
        {
            $ToWrite = $File.FullName.Substring($AmountToTrim).ToLower()
            $Data = [System.Text.Encoding]::Unicode.GetBytes($ToWrite)
            $CryptoStream.Write($Data, 0, $Data.Length)
        }

        # encode the hashed data of each file
        ForEach ($File in $Files)
        {
            $ToWrite = (Get-FileHash -Path $File.FullName).Hash
            $Data = [System.Text.Encoding]::Unicode.GetBytes($ToWrite)
            $CryptoStream.Write($Data, 0, $Data.Length)
        }
    }

    # finialize the stream and return the overall hash
    $CryptoStream.FlushFinalBlock()
    $CryptoStream.Dispose()
    Return [System.BitConverter]::ToString($Alg.Hash).Replace('-','')
}

<#
.SYNOPSIS

This function recreates the source directory of a package using the 
content library from an SCCM server.

.PARAMETER ContentServer

The -ContentServer specifies the CM server that contains the content library.
This is usually a distribution point but can also be a site server that is 
not a distribution point since site servers must maintain a copy of the 
content files.

.PARAMETER PackageId

The package ID of the package to extract.  

.PARAMETER OutputPath

The parameter specifies the output path that the package will be written to.
This path does not not need exist and, if it does exist, it should be empty.
If you wish to output the package to an existing directory, see -Force.
    
.PARAMETER UseWmiMethod

This parameter instructs script to use an SCCM native WMI function to extract
the package.  When this option is used, the LocalSystem account on the server 
is used to do the extraction and therefore any path specified by -OutputPath 
will be in context of the SCCM server itself.  For example, if this function is
called from a remote system and -UseWmiMethod is used with -OutputPath is set 
to 'C:\MyPackage', then 'C:\MyPackage' will actually be created on the SCCM 
server itself and the local drive on the remote system.  Similiarly, if a UNC 
path is specified, the SCCM server's LocalSystem account (i.e., the Active 
Directory computer object) must be able to access that path specified and have
permissions to write data to it.

.PARAMETER DoVerification

This parameter causes SCCM to calculate a hash for the entire output directory
after extraction and checks to see if it matches the package hash stored in the
content library.  This hash calculation is done with the Get-CMDirectoryHash.

.PARAMETER Force

This parameter allows the caller to overwrite an existing directory.  The
script does not remove files if -Force is used; it simply overwrites any
files that happen to conflict with the files in the package.  

.NOTES

If your package contains long file names, you will have to enable long file
name support for PowerShell for function to properly extract and verify the
extracted files.  This limitation does not apply when the -UseWmiMethod method
is used since the extraction is done using the native functionality of SCCM.
When using -UseWmiMethod and PowerShell is not configured for long file
name support, the -DoVerification may report a false negative since it 
relies on PowerShell being able to access all files.

.EXAMPLE

Get-CMPackageFromContentLibrary -ContentServer 'MyServer' -PackageId XYZ00001
   -OutputDirectory 'C:\MyPackages\MyPackage' -DoVerification 
#>
Function Global:Get-CMPackageFromContentLibrary
{
    # define function parameters
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)][string]$ContentServer,
        [Parameter(Mandatory)][string]$PackageId,
        [Parameter(Mandatory)][string]$OutputPath,
        [switch]$UseWmiMethod = $false,
        [switch]$DoVerification = $false,
        [switch]$Force = $false
    )

    # verify the output directory does not exist or is empty
    If ($Force -eq $false -and `
        (Test-Path -LiteralPath $OutputPath) -and `
        @(Get-ChildItem -Force -LiteralPath $OutputPath).Count -gt 0)
    {
        Throw 'Specified output path exists and is not empty. ' +
           'Use -Force to override this check. Warning: Use of -DoVerification ' +
           'with -Force may report a false negative if outputting to a ' +
           'directory with unrelated files in it since they will be included in ' +
           'the hash verification process.'
    }

    # generate a path to the content library of a server
    $MainContentLib = [System.IO.Path]::Combine("\\$ContentServer", 'SCCMContentLib$')

    # construct the path to the ini file in the pkglib directory
    $PkgLibPath = Join-Path -Path $MainContentLib -ChildPath 'PkgLib'
    $PkgIniPath = Join-Path -Path $PkgLibPath -ChildPath "${PackageId}.INI"
    Write-Verbose "Discovered Package Library Path: $PkgLibPath"
    
    # return immediately if package information could not be found
    If (-not (Test-Path -LiteralPath $PkgIniPath))
    {
        Throw "Package $PackageId could not be located in PkgLib."
    }

    # fetch the latest version of the package
    $PkgIniData = Get-CMIniContentPath -Path $PkgIniPath
    
    # there are two main types of packages: those with single, versioned sets 
    # of files and those with multiple sets of files 
    $SupportMultipleContent = $false
    $ContentReferences = @()
    If ($PkgIniData['Info'].ContainsKey('Version'))
    {
        $PkgVersion = $PkgIniData['Info']['Version']
        $ContentReferences = "${PackageId}.${PkgVersion}"
    }
    Else
    {
        $SupportMultipleContent = $true
        $ContentReferences = $PkgIniData['Packages'].Keys
    }

    # construct the path to the datalib area under the content library
    $PkgDataLib = Join-Path -Path $MainContentLib -ChildPath 'DataLib'
    Write-Verbose "Discovered Package Data Library Path: $PkgDataLib"

    # get the file lib area(s) - this may actually be multiple drives
    # since they span multiple drives
    $FileLibPaths = Get-CMFileLibPaths -ContentServer $ContentServer

    # enumerate each content area
    ForEach ($ContentReference in $ContentReferences)
    {
        # in the case of package with multiple content directories, use the
        # content reference as a subfolder within the folder
        If ($SupportMultipleContent)
        {
            $ContentOutputPath = (Join-Path -Path $OutputPath -ChildPath $ContentReference)
        }
        Else
        {
            $ContentOutputPath = $OutputPath
        }

        # ensure output directory exists
        New-Item -ItemType Directory -Path $ContentOutputPath -Force | Out-Null
        $ContentOutputPath = (Get-Item -LiteralPath $ContentOutputPath).FullName

        # verify the content data file exist
        $DataPath = Join-Path -Path $PkgDataLib -ChildPath $ContentReference
        If (-not (Test-Path -LiteralPath "${DataPath}.INI") -or -not (Test-Path -LiteralPath $DataPath))
        {
            Throw "Package $PackageId/$ContentReference could not be located in DataLib."
        }

        # fetch the full versioned package information
        $PkgVerIniData = Get-CMIniContentPath -Path "${DataPath}.INI"

        # if user has requested to use the native wmi method of extraction
        If ($UseWmiMethod)
        {
            # setup the parameters for the wmi method that the method requires
            # and then translate the named list to an ordered list since the powershell
            # wmi method does not support named parameter lists
            $NamedArguments = @{}
            $NamedArguments['ContentID'] = $ContentReference
            $NamedArguments['ContentTypePackage'] = $False
            $NamedArguments['Destination'] = $ContentOutputPath
            $ArgumentList = Get-WmiOrderedListFromNamedArguments -ComputerName $ContentServer `
                -Namespace 'ROOT\SCCMDP' -Class 'SMS_DistributionPoint' -Method 'ExpandContent' `
                -NamedArguments $NamedArguments

            # use the built-in wmi function to expand the 
            Invoke-WmiMethod -Namespace 'ROOT\SCCMDP' -Class 'SMS_DistributionPoint' `
                -Name 'ExpandContent' -ComputerName $ContentServer -ArgumentList $ArgumentList 
            If ($? -eq $False)
            {
                Throw 'Package $PackageId could not be expanded.'
            }
        }
        Else
        {
            # pre-create the directory structure
            ForEach ($File in Get-ChildItem -Directory -Recurse -LiteralPath $DataPath)
            {
                $RelativePath = $File.FullName.Substring($DataPath.Length)
                $NewPath = Join-Path -Path $ContentOutputPath -ChildPath $RelativePath
                New-Item -ItemType Directory -Path $NewPath -Force | Out-Null
            }

            # enumerate the source path
            ForEach ($File in Get-ChildItem -File -Recurse -LiteralPath $DataPath -Filter '*.INI')
            {
                # strip the path down to a relative path and construct the new path
                $RelativePath = Join-Path -Path $File.Directory.FullName -ChildPath $File.BaseName 
                $RelativePath = $RelativePath.Substring($DataPath.Length)

                # get the attributes (hash, size, modified time)
                $FileIniData = Get-CMIniContentPath -Path $File.FullName

                # new path based on output directory
                $FullOutputPath = Join-Path -Path $ContentOutputPath -ChildPath $RelativePath
        
                # generate that path to the hash directory entry
                $FileHash = $FileIniData['File']['Hash']

                # loop through the libraries looking for the one with the file
                $FileFound = $false
                ForEach ($FileLibPath in $FileLibPaths)
                {
                    # create the potential path
                    $HashPath = [IO.Path]::Combine($FileLibPath,$FileHash.Substring(0,4),$FileHash)

                    # continue to the next path
                    If (-not (Test-Path $HashPath)) { Continue }
        
                    # copy the file to its destination
                    $Item = Copy-Item -LiteralPath $HashPath -Destination $FullOutputPath -Force

                    # apply the attribute information
                    [System.IO.File]::SetAttributes($FullOutputPath,
                        [UInt32]::Parse($FileIniData['File']['Attributes'],[System.Globalization.NumberStyles]::AllowHexSpecifier))

                    # apply the date information
                    [System.IO.File]::SetLastWriteTimeUtc($FullOutputPath,
                        [DateTime]::FromFileTimeUtc([long] $FileIniData['File']['TimeModified']))

                    # note the file was found
                    $FileFound = $true
                }

                # if file was not found, alert
                if (-not $FileFound)
                {
                    Throw "File Not Found: " + $RelativePath
                }
            }
        }

        # do the hash check verification
        If ($DoVerification)
        {
            # use the native to hash our output directory
            $DirectoryHash = Get-CMDirectoryHash -Path $ContentOutputPath 

            # compare the full package hash as recorded in the library
            if ($DirectoryHash -eq $PkgVerIniData['Info']['Hash'])
            {
                Write-Host -ForegroundColor Green "$PackageID/$ContentReference verification successful."
            }
            else
            {
                Write-Host -ForegroundColor Red "$PackageID/$ContentReference verification failed."
                Write-Host -ForegroundColor Red "Directory Hash: ${DirectoryHash}."
                Write-Host -ForegroundColor Red "Library Hash: $($PkgVerIniData['Info']['Hash'])."
            }
        }
    }
}

Export-ModuleMember -Function Get-CMDirectoryHash
Export-ModuleMember -Function Get-CMPackageFromContentLibrary

# end module
} | Out-Null

# if this file is executed without any parameters then display help
If (-not (Test-Path Variable:PSIse) -and $Args.Count -eq 0)
{
    Get-Help Get-CMPackageFromContentLibrary
}

# if command line arguments where passed then run them
ElseIf ($Args.Count -gt 0)
{
    Invoke-Expression "Get-CMPackageFromContentLibrary $Args"
}
