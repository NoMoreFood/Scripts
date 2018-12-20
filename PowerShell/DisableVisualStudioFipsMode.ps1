<#
.SYNOPSIS

Use of FIPS mode within Visual Studio can cause unexpected crashses.

This script disables FIPS compliance mode by enumerating all locatable Visual 
Studio installations and adding the configuration/runtime/enforceFIPSPolicy 
element with the value enabled=false to any executable's config file.  Setting 
this value will override the global FIPS policy set within Windows security 
policy,  thereby allowing an administrator maintain the global policy for other 
applications.

This file must be executed as an administrator in order to update the program
files within the Visual Studio directory.  It is recommended to re-run this 
after any Visual Studio update as these changes may have been reverted.

In most cases, changing this setting is only absolutely necessary on particular 
executables that use FIPS non-compliant algorithmns such as 
ServiceHub.VSDetouredHost.exe.config but there is no known issue with setting 
the setting more broadly in Visual Studio.

Another alternative to changing these configuration files is to disable FIPS
enforcement is by detouring the FIPS registry key reads by devenv.exe and its
child processes.  This can be done with my other utility called WinPriv.  For 
example, WinPriv.exe /FipsOff "C:\...\devenv.exe".  Google 'WinPriv'. 

Please be aware this changes are not endorsed nor supported by Microsoft.

.NOTES

PowerShell -File DisableVisualStudioFipsMode.ps1

Author: Bryan Berns (Bryan.Berns@gmail.com).  

#>

#Requires -Version 3
Set-StrictMode -Version 2.0

# run vswhere to determine valid locations of visual studio
$VsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$VsWhereOutput = [System.IO.Path]::GetTempFileName()
$VsWhereInfo = Start-Process $VsWhere -NoNewWindow -Wait -ArgumentList @('-property','installationPath') -PassThru -RedirectStandardOutput $VsWhereOutput
If ($VsWhereInfo.ExitCode -ne 0) 
{
    Write-Host -ForegroundColor Red ('Unable To Execute VsWhere To Determine Location.')
}

# read paths from output of vswhere command
$VsPaths = @(Get-Content $VsWhereOutput)
Remove-Item -LiteralPath $VsWhereOutput -Force

# process each visual studio installation
ForEach ($VsPath in $VsPaths)
{
    Write-Host -ForegroundColor Green ('Processing Install: ' + $VsPath)
    Set-Location $VsPath

    # process each file matching *.exe.config in the visual studio path
    ForEach ($VsFile in @(Get-ChildItem -Path $VsPath -File -Filter '*.exe.config' -Force -Recurse))
    {
        # note to the user which file were are processing
        $VsFileRelative = $VsFile.FullName | Resolve-Path -Relative
        Write-Host -ForegroundColor Green ('   Processing File: ' + $VsFileRelative)

        Try
        {
            # read and parse the xml file
            $Xml = [xml] (Get-Content -LiteralPath $VsFile.FullName)

            # see if the xml file already contains a enforce policy element
            If (($XmlNode = $Xml.SelectNodes('configuration/runtime/enforceFIPSPolicy')) -ne $null)
            {
                # add or update the enabled attribute
                $XmlNode.SetAttribute('enabled','false')
                $Xml.Save($VsFile.FullName)
            } `

            # locate the runtime key in which to add a enforce policy element
            ElseIf (($XmlNode = $Xml.SelectNodes('configuration/runtime')) -ne $null)
            {
                # add a enforce policy mode element and set the enabled attribute to false
                $XmlNode = $Xml.CreateElement('enforceFIPSPolicy')
                $XmlNode.SetAttribute('enabled','false')
                $Xml.configuration.runtime.AppendChild($XmlNode)
                $Xml.Save($VsFile.FullName)
            } 
        } 
        Catch
        {
            Write-Host -ForegroundColor Red ('ERROR: ' + $_.Exception.Message)
        }        
    }
}
