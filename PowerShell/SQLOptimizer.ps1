<#
.SYNOPSIS

SQL Optimizer is a set of PowerShell functions to analyze and remediate
index and heap fragmentation in SQL Server.

.HISTORY

1.0.0.0 - Initial Public Release 

.NOTES

The Invoke-SqlOptimization can be imported into your PowerShell session 
or the tool can be used from command line, batch file, or scheduled 
task as follows:

PowerShell -File SQLOptimizer.ps1 -Server "MySqlServer" [Other Params]

Author: Bryan Berns (Bryan.Berns@gmail.com).  

#>

#Requires -Version 3
Set-StrictMode -Version 2.0

<#
.SYNOPSIS

This is an internal function to to execute a SQL server.

.NOTES

If successful, this function will return $null if the specified query is a 
command and will return a array of rows if a standard query.  
#>
Function Script:Invoke-SqlQuery
{
    # define function parameters
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)][string] $Query, 
        [Parameter(Mandatory=$true)][System.Data.SqlClient.SqlConnection] $Connection,
        [switch] $IsCommand = $false
    )

    # setup the sql query and set the query timeout to the 
    # maximum value possible
    $ReturnInfo = $null
    $Command = $Connection.CreateCommand()
    $Command.CommandText = $Query
    $Command.CommandTimeout = [int]::MaxValue 

    # if an error occurs then it is not actually caught here;  it will be 
    # thrown to the calling function
    Try
    {
        # if verbose, print out what we are going to execute
        Write-Verbose "SQL Query: $Query"

        # if this is a command (vice a standard query), there is no data
        # to return and we just need to execute the query.  
        If ($IsCommand)
        {
            If (-not ($WhatIfPreference))
            {
                $Command.ExecuteNonQuery() | Out-Null
            }
        }

        # standard queries will return data
        Else
        {
            # execute the query
            $Result = $Command.ExecuteReader() 

            # load the returned data into a table
            $Table = New-Object System.Data.DataTable
            $Table.Load($Result) 
            $ReturnInfo = $Table.Rows
            $Table.Dispose()
        }
    }
    Finally
    {
        # cleanup
        $Command.Dispose()
    }

    Return $ReturnInfo
}

<#
.SYNOPSIS

This is an internal function to establish a connection with a SQL server.
#>
Function Script:Get-SqlConnection
{
    # define function parameters
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)][string] $Server,
        [switch] $RequireDedicatedAdminConsole,
        [int] $ConnectionTimeout=5
    )

    # create a new connection object and generate new connection string to use.
    # this is currently setup to use using windows integrated authentication.  
    $Connection = New-Object System.Data.SqlClient.SqlConnection
    $Connection.ConnectionString = @("Server=$Server",
        "Integrated Security=True", "Connection Timeout=$ConnectionTimeout") -join ';'

    # attempt the connection - this will throw terminate and throw an exception 
    # if the connection is not successful
    $Connection.Open()

    # in order to optimize internal indexes, we need to be running on the  
    # dedicated admin connnection.  we need to lookup the currently connection 
    # session to determine if that is how we connected
    If ($RequireDedicatedAdminConsole)
    {
        $Result = Invoke-SqlQuery -Connection $Connection -Query `
            ('SELECT endpoints.is_admin_endpoint as is_dac ' + `
                'FROM [sys].[tcp_endpoints] as endpoints ' + `
                'JOIN [sys].[dm_exec_sessions] as sessions ' + `
                'ON endpoints.endpoint_id = sessions.endpoint_id ' + `
                'WHERE sessions.session_id = @@spid')

        # if we are current currently trying to use a dedicated admin connect then 
        # try to reconnect using the 'ADMIN:' qualifier
        If ($Result['is_dac'] -eq 0)
        {
            # close the existing connection since we are going to try to 
            # open a new one to the dedicated admin connection
            $Connection.Close()

            # generate a new connection string using the ADMIN: qualifier
            # the browser service should then rely the port for the admin connection
            $Connection.ConnectionString = @("Server=ADMIN:$Server",
                "Integrated Security=True", "Connection Timeout=$ConnectionTimeout") -join ';'

            # attempt the connection
            Try 
            {
                $Connection.Open()
            } 
            Catch 
            { 
                # rethrow the connection with some guidance about the dedicated 
                # admin connection
                throw ('Unable to establish a connection to the SQL server.' + 
                    'Using -IncludeInternalIndexes requires you to be using ' + 
                    'the Dedicated Admin Connection (DAC).  If you are running this command ' +
                    'remotely, then try enabling remote admin connection or switch to ' +
                    'running the command locally on the SQL server. For Express Edition ' + 
                    'instances, a special trace flag must be used in the startup parameters ' + 
                    'in order to enabled the DAC.')
            }
        }
    }

    # return the connection object
    Return $Connection
}

<#
.SYNOPSIS

This function returns fragmentation on heaps and indexes in SQL instance.

.PARAMETER Server

The -Server parameter specifies a SQL instance to query.  This string can
be a server name or a server instance (e.g., MyServer\MyInstance).  A server 
name followed by a port (MyServer,1433) is also valid.

.PARAMETER FragmentationMinimum

The -FragmentationMinimum parameter will limit the function to return 
indexes / heaps with at least the specified level of fragementation in 
percent.  

.PARAMETER PageCountMinimum

The -PageCountMinimum parameter will limit the function to return 
indexes / heaps with at least the specified page count.  The page count
roughly corresponds to the size of the table. Due to how SQL server 
arranges table, is not important and potentially not possible to 
obtain low fragmentation values on tables with low page counts.
    
.PARAMETER All

Using -All provides an easy way to specify -FragmentationMinimum 0
and -PageCountMinimum 0, thereby returning any statistics available.

.PARAMETER Connection

This parameter allows the caller to use an existing connection object
to query the SQL database instead of creating a new connection to 
the server specified by the -Server option.  This was designed for 
internal use to minimize database connections.

.NOTES

This function will not return fragmentation for internal tables. 
Please contact the script author if you are aware of a way to query 
and would like to see it integrated into this script.

Specifying -Verbose will display the SQL queries that are used for querying 
the database.

.EXAMPLE

Get-SqlFragmentation -Server 'MyServer'

Queries the databases on 'MyServer' for fragmentation information on all 
indexes that meet the default minimum filtering values.

.EXAMPLE

Get-SqlFragmentation -Server 'MyServer' -All

Queries the databases on 'MyServer' for fragmentation information on all 
indexes regardless of their current fragmentation state or page count size.

#>
Function Global:Get-SqlFragmentation
{
    # define function parameters
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)][string] $Server,
        [int]$FragmentationMinimum = 10,
        [int]$PageCountMinimum = 1000,
        [switch] $All = $false,
        [Parameter(DontShow)][System.Data.SqlClient.SqlConnection] $Connection = $null
    )

    # process overrides when using -All
    If ($All)
    {
        $FragmentationMinimum = 0
        $PageCountMinimum = 0
    }

    # only open a new connection for sql if one was not already passed
    $CleanupConnection = $false
    If ($Connection -eq $null)
    {
        Try 
        {
            # establish a new connection
            $Connection = Get-SqlConnection -Server $Server 
            $CleanupConnection = $true
        } 
        Catch 
        { 
            # report errors and return
            Write-Error $_.Exception.Message
            Return 
        }
    }

    # generate a list of online databases
    $DatabaseInfoRows = Invoke-SqlQuery -Connection $Connection -Query `
        'SELECT name FROM [master].[sys].[databases] WHERE state = 0 AND is_read_only = 0'
    If ($DatabaseInfoRows -eq $null)
    {
        Write-Error ("Problem occured trying to query list of databases.")
        If ($CleanupConnection -eq $True) { $Connection.Close(); }
        Return
    }

    # enumerate each database
    $FragmentationInfo = @()
    ForEach ($DatabaseName in ($DatabaseInfoRows | ForEach-Object { $_['name'] }))
    {
        # construct a query to return fragmentation for the specified database
        # this query results the names of the schema, table, index and the
        # average framentation of the index or heap.  if the user has specified
        # a particular minimum page count or fragmentation percentage
        $Query = `
            "DECLARE @dbid int; SELECT @dbid = DB_ID('$DatabaseName'); " +
            "SELECT OBJECT_SCHEMA_NAME(i.object_id,@dbid) as sname, " +
                "OBJECT_NAME(i.object_id,@dbid) as tname, i.name AS iname, s.page_count, " + 
                "CAST(ROUND(avg_fragmentation_in_percent,2) AS NUMERIC(5,2)) AS frag " +
            "FROM sys.dm_db_index_physical_stats(@dbid,NULL,NULL,NULL,NULL) s " + 
            "LEFT JOIN [$DatabaseName].[sys].[indexes] i " +
                "ON i.object_id = s.object_id AND i.index_id = s.index_id " + 
            "WHERE OBJECT_NAME(i.object_id,@dbid) NOT LIKE '#%' " + 
                "AND s.page_count >= $PageCountMinimum " +
                "AND s.avg_fragmentation_in_percent >= $FragmentationMinimum " + 
                "AND s.fragment_count IS NOT NULL"

        # query the database for the index information
        $IndexInfoRows = @(Invoke-SqlQuery -Connection $Connection -Query $Query)
        If ($IndexInfoRows -eq $null)
        {
            report to the user if an error occured
            Write-Error "Problem occured trying to query list of indexes in $DatabaseName"
            If ($CleanupConnection -eq $True) { $Connection.Close(); }
            Return
        }

        # enumerate each row and construct a array of objects that have a fully
        # qualified name for the index and its full qualified index name
        ForEach ($IndexInfo in $IndexInfoRows)
        {
            $Name = '[' + $DatabaseName + '].[' + $IndexInfo['sname'] + `
                '].[' + $IndexInfo['tname'] + '].[' + $IndexInfo['iname'] + ']'
            $FragmentationInfo += New-Object PSObject –Property `
                ([ordered]@{'Name'=$Name;'Fragmentation'=$IndexInfo['frag']; 
                  'PageCount'=$IndexInfo['page_count']})
        }
    }
    
    # cleanup and return the fragmentation info
    If ($CleanupConnection -eq $True) { $Connection.Close(); }
    Return $FragmentationInfo | Sort-Object Name
}

<#
.SYNOPSIS

This function performs index and heap optimizationon on objects in a
specified SQL instance.

.PARAMETER Server

The -Server parameter specifies a SQL instance to query.  This string can
be a server name or a server instance (e.g., MyServer\MyInstance).  A server 
name followed by a port (MyServer,1433) is also valid.

.PARAMETER FragmentationMinimum

The -FragmentationMinimum parameter will limit the function to optimize 
indexes / heaps with at least the specified level of fragementation in 
percent.  

.PARAMETER PageCountMinimum

The -PageCountMinimum parameter will limit the function to optimize indexes 
and heaps with at least the specified page count.  The page count roughly 
corresponds to the size of the table. Due to how SQL server arranges tables, 
is not important and potentially not possible to obtain low fragmentation 
values on tables with low page counts.

.PARAMETER IncludeInternalIndexes

The -IncludeInternalIndexes parameter attempts to include special, internal
tables that are used for behind-the-scenes operation such as Change Tracking. 
These are referenced within the called sys.internal_tables.  There appears
to be know known way to query fragmentation statistics on these tables so 
including this parameter will unconditionally include these tables.  The 
depecrated 'DBCC' commands are used to perform optimization on these tables.

.PARAMETER IncludeSystemDatabases

The -IncludeSystemDatabases parameter includes the processing of tables within the 
Microsoft default, built-in databases such as master, model, msdb, and tempdb.

.PARAMETER DoOfflineOperations

The -DoOfflineOperations parameter will perform optimization using rebuild
operations.  Using this option does not take the database offline but may 
impact access to the specific index this is actively being rebuilt.  Depending
on the index size and SQL server resources, this can take a few milliseconds up
to several minutes or more.  Is it recommended this only be used during planned
maintenance periods.

.PARAMETER UseEnterpriseEditionFeatures

The -UseEnterpriseEditionFeatures allows SQL server to perform rebuild operations
without impacting access to the index being rebuilt.  When specified, this 
PowerShell function still only enables these features if the specified server
is actually running Enterprise Edition.  Not all indexes can be rebuilt online.
This flag is ignored when the -DoOfflineOperations is specified.

.PARAMETER All

The -All parameter is a shortcut parameter that automatically runs the command
with -FragmentationMinimum 0 -PageCountMinimum 0 -IncludeSystemDatabase 
-DoOfflineOperations -IncudeInternalTables.

.NOTES

Specifying -Verbose will display the SQL queries that are used for querying 
and optimizing the database.

.EXAMPLE

Invoke-SqlOptimize -Server 'MyServer'

Optimizes the indexes for all user databases on 'MyServer'. Only indexes that
meet the default minimum filtering values are processed.

.EXAMPLE

Invoke-SqlOptimize -Server 'MyServer' -FragmentationMinimum 0 -PageCountMinimum 0 
-IncludeSystemDatabase -DoOfflineOperations -IncudeInternalTables

Attempts to rebuild all indexes on MyServer regardless of index status or 
current fragmentation level.

#>
Function Global:Invoke-SqlOptimization
{
    # define function parameters
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param
    (
        [Parameter(Mandatory=$true)][string] $Server,
        [string] $Database = '*',
        [int] $FragmentationMinimum = 10,
        [int] $PageCountMinimum = 1000,
        [switch] $IncludeInternalIndexes = $false,
        [switch] $IncludeSystemDatabases = $false,
        [switch] $DoOfflineOperations = $false,
        [switch] $UseEnterpriseEditionFeatures = $false,
        [Parameter(DontShow)][switch] $All = $false
    )

    # process overrides when using -All
    If ($All)
    {
        $FragmentationMinimum = 0
        $PageCountMinimum = 0
        $IncludeInternalIndexes = $true
        $IncludeSystemDatabases = $true
        $DoOfflineOperations = $true
    }

    # using the database or replica lookup the toplevel server
    Try 
    {
        $Connection = Get-SqlConnection -Server $Server `
            -RequireDedicatedAdminConsole:$IncludeInternalIndexes
    } 
    Catch 
    { 
        Write-Error $_.Exception.Message
        Return
    }

    # query the sql instance for a list of databases that it serves
    $DatabaseInfoRows = Invoke-SqlQuery -Connection $Connection -Query `
        'SELECT name FROM [master].[sys].[databases] WHERE state = 0 AND is_read_only = 0'
    If ($DatabaseInfoRows -eq $null)
    {
        Write-Error ("Problem occured trying to query list of databases.")
        $Connection.Close();
        Return
    }

    # lookup all database names served on this instance
    $DatabaseNames = @()
    ForEach ($DatabaseInfo in $DatabaseInfoRows)
    {
        # add the database name to the list unless it is a system
        # database and we are excluding system databases
        If ($IncludeSystemDatabases -or @('master','model','msdb','tempdb') -notcontains $DatabaseInfo['name'])
        {
            $DatabaseNames += $DatabaseInfo['name']
        }
    }

    # if a specific database was specified, then just reset the array to 
    # just do that database instead of all database in the sql instance
    If ($Database -ne '*')
    {
        If ($DatabaseNames -contains $Database)
        {
            $DatabaseNames = @($Database)
        }
        Else
        {
            Write-Error 'The specified database could not be located on the specified instance.'
            $Connection.Close()
            Return
        }
    }

    # start to construct the list tables to reindex
    $IndexNames = @()
    $IndexNamesInternal = @()
    ForEach ($DatabaseName in $DatabaseNames)
    {
        # construct the sql query to get all fully qualified database names
        $Query = `
            "SELECT OBJECT_SCHEMA_NAME(o.object_id,DB_ID('$DatabaseName')) AS sname, " + 
                "o.name as tname, i.name as iname, o.type, o.is_ms_shipped " + 
            "FROM [$DatabaseName].[sys].[objects] o " +
            "INNER JOIN [$DatabaseName].sys.indexes i ON o.object_id = i.object_id " + 
            "WHERE o.name NOT LIKE '#%' AND o.type IN ('IT','U','V')"
    
        # perform the query 
        $IndexInfoRows = Invoke-SqlQuery -Connection $Connection -Query $Query
        If ($IndexInfoRows -eq $null)
        {
            Write-Error "Problem occured trying to query list of tables in $DatabaseName"
            $Connection.Close();
            Return
        } 
    
        # append the fully qualified path to the table
        ForEach ($IndexInfo in $IndexInfoRows)
        {
            $SchemaName = $IndexInfo['sname']
            $TableName = $IndexInfo['tname']
            $IndexName = $IndexInfo['iname']
            $QualifiedName = "[$DatabaseName].[$SchemaName].[$TableName].[$IndexName]"

            # ignore interal indexes if requested
            If ($IndexInfo['type'] -eq 'IT')
            {
                If (-not $IncludeInternalIndexes) { Continue }
                $IndexNamesInternal += $QualifiedName
            } 
            
            # add the index name to the list of indexes to proces
            $IndexNames += $QualifiedName
        }
    }

    # sort the index list
    $IndexNames = @($IndexNames | Sort-Object)

    # query fragmentation information so we know which indexes that
    # we should run optimization against and parse out just the names
    $FragmentationInfo = Get-SqlFragmentation -Server 'Ignored' `
        -Connection $Connection -FragmentationMinimum $FragmentationMinimum `
        -PageCountMinimum $PageCountMinimum
    $FragmentedIndexes = @($FragmentationInfo | ForEach-Object { $_.Name })
    
    # check to see if there is an enterprise edition
    # if we are running enterprise edition then we can
    # do rebuilds online instead of just reorganizing
    $EditionRow = Invoke-SqlQuery -Connection $Connection -Query "SELECT SERVERPROPERTY('EngineEdition')"
    $IsEnterpriseEdition = $UseEnterpriseEditionFeatures -eq $true -and $EditionRow[0] -eq 3

    # for statistics
    $CountSuccess = 0
    $CountFailure = 0

    # enumerate each table name and try to do the 
    # optimization
    ForEach ($IndexName in $IndexNames)
    {
        If (($IndexNamesInternal -notcontains $IndexName) -and `
            ($FragmentedIndexes -notcontains $IndexName))
        {
            Continue
        }

        # perform the query 
        $NameParts = $IndexName -split '[.]'
        $DatabaseNameUndecorated = $NameParts[0].TrimStart('[').TrimEnd(']')
        $TableName = $NameParts[0..2] -join '.'
        $IndexShortName = $NameParts[3]
        $IndexShortNameUndecorated = $IndexShortName.TrimStart('[').TrimEnd(']')

        # report to the user what is going on
        Write-Host -ForegroundColor Green ("Optimizing: $IndexName")

        If ($DoOfflineOperations)
        {   
            If ($IndexNamesInternal -contains $IndexName)
            {
                $Query = "DBCC DBREINDEX('$TableName','$IndexShortNameUndecorated')"
            }
            Else
            {
                $Query = "ALTER INDEX $IndexShortName ON $TableName REBUILD"
            }

        }
        Else
        {
            If ($IndexNamesInternal -contains $IndexName)
            {
                $Query = "DBCC INDEXDEFRAG ('$DatabaseNameUndecorated','$TableName','$IndexShortNameUndecorated')"
            }
            Else
            {
                If ($IsEnterpriseEdition)
                {
                    $Query = "ALTER INDEX $IndexShortName ON $TableName REBUILD WITH (ONLINE = ON)"
                }
                Else
                {
                    $Query = "ALTER INDEX $IndexShortName ON $TableName REORGANIZE"
                }
            }
        }

        # special case for heaps
        If ($IndexShortName -eq '[]')
        {
            If ($DoOfflineOperations)
            {
                $Query = "ALTER TABLE $TableName REBUILD"
            }
            ElseIf ($IsEnterpriseEdition)
            {
                $Query = "ALTER TABLE $TableName REBUILD WITH (ONLINE = ON)"
            }
            Else
            {
                # no online option available; skipping
                Write-Host -ForegroundColor Yellow "WARNING: Could not optimize heap $IndexName online."
                Write-Host -ForegroundColor Yellow "         Some heaps can be rebuilt online using enterprise edition freatures."
                $CountFailure++
                Continue
            }
        }

        # perform the optimization query
        Try
        {
            $Result = Invoke-SqlQuery -IsCommand -Connection $Connection -Query $Query 
            $CountSuccess++
        }
        Catch
        {
            $Result = $_.Exception.InnerException.Number 
            Write-Host -ForegroundColor Yellow "WARNING: Could not optimize $IndexName (SQL Error: $Result)."
            If ($Result -eq 2725 -or $Result -eq 2552)
            {
                Write-Host -ForegroundColor Yellow "         This index or heap can only be rebuilt offline."
            }
            $CountFailure++
        }
    }

    Write-Host -ForegroundColor Cyan ('---------------------------------------')
    Write-Host -ForegroundColor Cyan ('Indexes/Heaps Processed: ' + ($CountSuccess + $CountFailure))
    Write-Host -ForegroundColor Cyan ('Successes: ' + $CountSuccess)
    Write-Host -ForegroundColor Cyan ('Failures: ' + $CountFailure)
    $Connection.Close();
}

# if this file is executed without any parameters then display help
If (-not (Test-Path Variable:PSIse) -and $Args.Count -eq 0)
{
    Get-Help Invoke-SqlOptimization 
}

# if command line arguments where passed then run them
ElseIf ($Args.Count -gt 0)
{
    Invoke-Expression "Invoke-SqlOptimization $Args"
}