# ------------------------------------------
# Function:  Invoke-HuntSQLServers
# ------------------------------------------
# Author: Scott Sutherland, NetSPI
# License: 3-clause BSD
# Version 1.3.15
# Requires PowerUpSQL
<#
Change data tables to psobjects and write to file using append
Add findings for sp and agent passwords
Add new test for linked servers
Add new test for dangerious xp
#>
function Invoke-HuntSQLServers
{
    <#
            .SYNOPSIS
            This function wraps around PowerUpSQL functions to inventory access to SQL Server instances associated with
            Active Directory domains, and attempts to enumerate sensitive data.
            .PARAMETER Username
            Domain account to authenticate to Active Directory.
            .PARAMETER Password
            Domain password to authenticate to Active Directory.
            .PARAMETER DomainController
            Domain controller to authenticated to. Requires username/password or credential.
            .PARAMETER Threads
            Number of concurrent tasks to run at once. Default 20.
            .PARAMETER SampleThreads
            Number of concurrent tasks to run on each database during sampling. Default 20.
            .PARAMETER CheckMgmt
            Perform SPN discovery of MSServerClusterMgmtAPI SPN as well.  This is much slower.
            .PARAMETER CheckAll
            Attempt to log into all identify instances even if they dont respond to UDP requests.
            .PARAMETER Output Directory
            File path where all csv and html report will be exported.
            .PARAMETER TargetsFile
            Path to file containing a list of target computers.  One per line. If this is chosen the SPN discovery will not be conducted.
            .EXAMPLE
            Run as current domain user on domain joined system.  Only targets instances that respond to UDP scan.
            PS C:\> Invoke-HuntSQLServers -OutputDirectory C:\temp\
            .EXAMPLE
            Run as current domain user on domain joined system.  Only target computers in the provided list.
            PS C:\> Invoke-HuntSQLServers -OutputDirectory C:\temp\ -TargetsFile c:\temp\targets.txt
            .EXAMPLE
            Run as current domain user on domain joined system.  Target all instances found during SPN discovery.
            PS C:\> Invoke-HuntSQLServers -CheckAll -OutputDirectory C:\temp\
            .EXAMPLE
            Run as current domain user on domain joined system.  Target all instances found during SPN discovery.
            Also, check for management servers that commonly have unregistered instances via additional UDP scan.
            PS C:\> Invoke-HuntSQLServers -CheckAll -CheckMgmt -OutputDirectory C:\temp\
            .EXAMPLE
            Run as current domain user on domain joined system.  Target all instances found during SPN discovery.
            Also, check for management servers that commonly have unregistered instances via additional UDP scan.
			Also, export to a Resolve importable format.
            PS C:\> Invoke-HuntSQLServers -CheckAll -CheckMgmt -OutputDirectory C:\temp\ 		
             .EXAMPLE
            Run as alernative domain user against alertative domain:
            PS C:\> runas /netonly /user domain\user powershell_ise.exe
            PS C:\> import-module PowerUpSQL 
            PS C:\> Invoke-HuntSQLServers -CheckAll -OutputDirectory C:\temp\ -DomainController 192.168.1.1 -Username domain\user -Password MyPassword
            .EXAMPLE
            Full output example with export format.
            PS C:\> Invoke-HuntSQLServers -OutputDirectory C:\temp\ 

              ----------------------------------------------------------------
             | Invoke-HuntSQLServers                                          |
              ----------------------------------------------------------------
             |                                                                |
             | This function automates the following tasks:                   |
             |                                                                |
             | Instance Discovery                                             |
             | o Determine current computer's domain                          |
             | o Query the domain controller via LDAP for SQL Server instances|
             | o Filter for instances that respond to UDP scans               |
             |                                                                |
             | Access Discovery                                               |
             | o Filter for instances that can be logged into                 |
             | o Filter for instances that provide sysadmin access            |
             | o Identify potentially excessive role members (sysadmin)       |
             | o Identify shared SQL Server service accounts                  |
             | o Summarize versions that could be logged into                 |
             |                                                                |
             | Data Target Discovery: Database Targets                        |
             | o Filter based on database name                                |
             | o Filter based on database encryption                          |
             |                                                                |
             | Data Target Discovery: Sensitive Data                          |
             | o Social security numbers via column name                      |
             | o Credit card numbers via column name                          |
             |                                                                |
             | Data Target Discovery: Passwords                               |
             | o Passwords via column names                                   |
             | o Passwords in agent jobs (sysadmin)                           |
             | o Passwords in stored procedures (sysadmin)                    |
             |                                                                |
              ----------------------------------------------------------------
             | Note: This can take hours to run in large environments.        |
              ----------------------------------------------------------------
             [*] Results will be written to C:\temp\test1
             [*] Start time: 09/30/2001 12:59:51
             [*] Verifying connectivity to the domain controller
             [*] - Targeting domain domain.com
             [*] - Confirmed connection to domain controller myfirstdc.domain.com
             [*] -------------------------------------------------------------
             [*] INSTANCE DISCOVERY
             [*] -------------------------------------------------------------
             [*] Querying LDAP for SQL Server SPNs (mssql*).
             [*] - 100 SQL Server SPNs were found across 50 computers.
             [*] - Writing list of SQL Server SPNs to C:\temp\domain.com-SQL-Server-Instance-SPNs.csv
             [*] Performing UDP scanning 50 computers.
             [*] - 50 instances responded.
             [*] -------------------------------------------------------------
             [*] ACCESS DISCOVERY
             [*] -------------------------------------------------------------
             [*] Attempting to log into 50 instances found via SPN query.
             [*] - 25 could be logged into.
             [*] Listing sysadmin access.
             [*] - 2 SQL Server instances provided sysadmin privileges.
             [*] Attempting to grab role members from 4 instances.
             [*] - This usually requires special privileges
             [*] - 5 role members were found.
             [*] Identifying excessive role memberships.
             [*] - 5 were found.
             [*] Identifying shared SQL Server service accounts.
             [*] - 6 shared accounts were found.
             [*] Creating a list of accessible SQL Server instance versions.
             [*] - 3 versions were found that could be logged into.
             [*] -------------------------------------------------------------
             [*] DATABASE TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Querying for all non-default accessible databases.
             [*] - 10 accessible non-default databases were found.
             [*] Filtering for databases using transparent encryption.
             [*] -  2 databases were found using encryption.
             [*] Filtering for databases with names that contain ACH.
             [*] -  4 database names contain ACH.
             [*] Filtering for databases with names that contain finance.
             [*] -  1 database names contain finance.
             [*] Filtering for databases with names that contain chd.
             [*] -  6 database names contain chd.
             [*] Filtering for databases with names that contain enclave.
             [*] -  7 database names contain enclave.
             [*] Filtering for databases with names that contain pos.
             [*] -  2 database names contain pos.
             [*] -------------------------------------------------------------
             [*] SENSITIVE DATA TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Search accessible non-default databases for table names containing SSN.
             [*] - 1 table columns found containing SSN.
             [*] Search accessible non-default databases for table names containing CARD.
             [*] - 7 table columns found containing CARD.
             [*] Search accessible non-default databases for table names containing CREDIT.
             [*] - 3 table columns found containing CREDIT.
             [*] -------------------------------------------------------------
             [*] PASSWORD TARGET DISCOVERY
             [*] -------------------------------------------------------------
             [*] Search accessible non-default databases for table names containing PASSWORD.
             [*] - 4 table columns found containing PASSWORD.
             [*] Search accessible non-default databases for agent source code containing PASSWORD.
             [*] - 1 agent jobs containing PASSWORD.
             [*] Search accessible non-default databases for stored procedure source code containing PASSWORD.
             [*] - 0 stored procedures containing PASSWORD.
  
              ----------------------------------------------------------------
              SQL SERVER HUNT SUMMARY REPORT                                  
              ----------------------------------------------------------------
              Scan Summary                                                   
              ----------------------------------------------------------------
              o Domain     : DOMAIN.COM
              o Start Time : 09/30/2001 12:59:51
              o Stop Time  : 09/30/2001 13:00:17
              o Run Time   : 00:00:25.7371541
  
              ----------------------------------------------------------------
              Instance Summary                                               
              ----------------------------------------------------------------
              o 100 SQL Server instances found via SPN LDAP query.
              o 50 SQL Server instances responded to port 1434 UDP requests.
  
              ----------------------------------------------------------------
              Access Summary                                                 
              ----------------------------------------------------------------
  
              Access:
              o 25 SQL Server instances could be logged into.
              o 5 SQL Server instances provided sysadmin access.
              o 5 SQL Server role members were enumerated. *requires privileges
              o 5 excessive role assignments were identified.
              o 6 Shared SQL Server service accounts found.
  
              Below are the top 5:
              o 10 SQLSVC_PROD
              o  5 SQLSVC_UAT
              o  5 SQLSVC_QA
              o  2 SQLSVC_DEV
              o  2 SQLApp
  
              Below is a summary of the versions for the accessible instances:
              o 10 Standard Edition (64-bit)
              o  5 Express Edition  (64-bit)
              o 10 Express Edition           
  
              ----------------------------------------------------------------
              Database Summary                        
              ----------------------------------------------------------------
              o 10 accessible non-default databases were found.
              o 2 databases were found configured with transparent encryption.
              o 4 database names contain ACH.
              o 1 database names contain finance.
              o 6 database names contain chd.
              o 7 database names contain enclave.
              o 2 database names contain pos.
  
              ----------------------------------------------------------------
              Sensitive Data Access Summary                     
              ----------------------------------------------------------------
              o 1 sample rows were found for columns containing SSN.
              o 7 sample rows were found for columns containing CREDIT.
              o 3 sample rows were found for columns containing CARD.
  
              ----------------------------------------------------------------
              Password Access Summary                               
              ----------------------------------------------------------------
              o 4 sample rows were found for columns containing PASSWRORD.
              o 1 agent jobs potentially contain passwords. *requires sysadmin
              o 0 stored procedures potentially contain passwords. *requires sysadmin
  
              ----------------------------------------------------------------
             [*] Saving results to C:\temp\demo.com-SQLServer-Summary-Report.html			
    #>    
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user. For computer lookup.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user. For computer lookup.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against. For computer lookup.')]
        [string]$DomainController,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads to process at once.')]
        [int]$Threads = 20,
	
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of database sample threads to process at once.')]
        [int]$SampleThreads = 20,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Perform SPN discovery of MSServerClusterMgmtAPI SPN as well.  This is much slower.')]
        [switch]$CheckMgmt,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Attempt to log into all identify instances even if they dont respond to UDP requests.')]
        [switch]$CheckAll,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Directory to output files to.')]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Path to file containing a list of target computers.  One per line. If this is chosen SPN discovery will not be conducted.')]
        [string]$TargetsFile,

        [Parameter(Mandatory = $false,HelpMessage = 'Nova format switch.')]
        [switch]$Nova
    )

   Begin
   {        
        Write-Output "  ----------------------------------------------------------------" 
        Write-Output " | Invoke-HuntSQLServers                                          |"
        Write-Output "  ----------------------------------------------------------------"         
        Write-Output " |                                                                |"
        Write-Output " | This function automates the following tasks:                   |"
        Write-Output " |                                                                |"
        Write-Output " | Instance Discovery                                             |"
        Write-Output " | o Determine current computer's domain                          |"
        Write-Output " | o Query the domain controller via LDAP for SQL Server instances|"
        Write-Output " | o Filter for instances that respond to UDP scans               |"
        Write-Output " |                                                                |"
        Write-Output " | Access Discovery                                               |"
        Write-Output " | o Filter for instances that can be logged into                 |"
        Write-Output " | o Filter for instances that provide sysadmin access            |"
        Write-Output " | o Identify potentially excessive role members (sysadmin)       |"
        Write-Output " | o Identify shared SQL Server service accounts                  |"
        Write-Output " | o Summarize versions that could be logged into                 |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Database Targets                        |"
        Write-Output " | o Filter based on database name                                |"                     
        Write-Output " | o Filter based on database encryption                          |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Sensitive Data                          |"
        Write-Output " | o Social security numbers via column name                      |"
        Write-Output " | o Credit card numbers via column name                          |"
        Write-Output " |                                                                |"
        Write-Output " | Data Target Discovery: Passwords                               |"
        Write-Output " | o Passwords via column names                                   |"
        Write-Output " | o Passwords in agent jobs (sysadmin)                           |"
        Write-Output " | o Passwords in stored procedures (sysadmin)                    |"
        Write-Output " |                                                                |"
        Write-Output "  ----------------------------------------------------------------"  
        Write-Output " | Note: This can take hours to run in large environments.        |"
        Write-Output "  ----------------------------------------------------------------"
        Write-Output " [*] Results will be written to $OutputDirectory"        

        # Nova format
        If ($Nova) {
            Write-Verbose "Output will be in Nova format"
            $rMasterFindingId = "FindingTemplateSourceIdentifier"
            $rFindingName = "FindingName"
            $rAssetName = "AssetName" # This could eventually be updated to reflect a different Nova asset, e.g. 'AD Domain'.
        }else{
            $rMasterFindingId = "MasterFindingSourceIdentifier"
            $rFindingName = "InstanceName"
            $rAssetName = "AssetName" # R7 only has one option. 
        }

        # Verify PowerUpSQL was loaded
        $CheckForPowerUpSQL = Test-Path Function:\Get-SQLAuditDatabaseSpec
        if($CheckForPowerUpSQL -eq $false)
        {
            Write-Output " [-] This function requires PowerUpSQL: www.powerupsql.com"
	    Write-Output " [-] IEX(New-Object System.Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1`")"
            Write-Output " [!] Aborting execution."
            break
        }

        # Verify an output direcotry has been provided
        if(-not $OutputDirectory)
        {
            Write-Output " [-] -OutputDirectory parameter was not provided."
            Write-Output " [!] Aborting execution."
            break
        }

        # Get start time
        $StartTime = Get-Date
        Write-Output " [*] Start time: $StartTime"
        $StopWatch =  [system.diagnostics.stopwatch]::StartNew()

        # Verify domain controller connection        
        # Set target domain and domain  
        Write-Output " [*] Verifying connectivity to the domain controller"        
        if(-not $DomainController){
            
            # If no dc is provided then use environmental variables
            $DCHostname = $env:LOGONSERVER -replace("\\","")
            $TargetDomain = $env:USERDNSDOMAIN
        }else{                
            $DCRecord = Get-domainobject -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -DomainController $DomainController -Username $username -Password $Password | select -first 1 | select properties -expand properties -ErrorAction SilentlyContinue
            [string]$DCHostname = $DomainController
            [string]$DCCn = $DCRecord.cn
            [string]$TargetDomain = $DCHostname -replace ("$DCCn\.","") 
        }
                
        if($DCHostname)
        {
         Write-Output " [*] - Targeting domain $TargetDomain"
         Write-Output " [*] - Confirmed connection to domain controller $DCHostname"                         
        }else{
          Write-Output " [*] - There appears to have been an error connecting to the domain controller."
          Write-Output " [*] - Aborting."
          break
        }   
        
        # Create finding object
        $AllFindings = New-Object System.Data.DataTable
        $null = $AllFindings.Columns.Add("MasterFindingSourceIdentifier")  
        $null = $AllFindings.Columns.Add("InstanceName")
        $null = $AllFindings.Columns.Add("Instance")
        $null = $AllFindings.Columns.Add("AssetName") 
        $null = $AllFindings.Columns.Add("IssueFirstFoundDate")
        $null = $AllFindings.Columns.Add("VerificationCaption01") 
        $null = $AllFindings.Columns.Add("VerificationText01")       
   }

   Process
   {

        # ------------------------------------------
        # Instance Discovery
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] INSTANCE DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Check for provided list
        if(-not $TargetsFile) 
        {
            # Get SQL Server instances
            if($CheckMgmt){
                Write-Output " [*] Querying LDAP for SQL Server SPNs (mssql* and MSServerClusterMgmtAPI)."
                Write-Output " [*] - WARNING: You have chosen to target MSServerClusterMgmtAPI"
                Write-Output " [*]            It will yield more results, but will be much slower."
                $AllInstances = Get-SQLInstanceDomain -CheckMgmt -DomainController $DomainController -Username $Username -Password $Password 
            }else{
                Write-Output " [*] Querying LDAP for SQL Server SPNs (mssql*)."
                $AllInstances = Get-SQLInstanceDomain -DomainController $DomainController -Username $Username -Password $Password
            }
        
            $AllInstancesCount = $AllInstances.count
            $AllComputers = $AllInstances | Select ComputerName -Unique
            $AllComputersCount = $AllComputers.count
            Write-Output " [*] - $AllInstancesCount SQL Server SPNs were found across $AllComputersCount computers."

            # Save list of SQL Server instances to a file
            write-output " [*] - Writing list of SQL Server SPNs to $OutputDirectory\$TargetDomain-SQL-Server-Instance-SPNs.csv"
            $AllInstances | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-All.csv"
        }else{
            
            # Status user
            Write-Output " [*] Attempting to read target computers from $TargetsFile." 
            Write-Output " [*] SPN discovery will not be conducted." 

            # Verify file path
            if(-not (Test-Path $TargetsFile))
            {
                Write-Output " [*] - $TargetsFile is not accessible or does not exist. Aborting."
                Break                        
            }

            # Import list            
            $AllComputers = gc $TargetsFile |  
            foreach {             
                $object = New-Object PSObject 
                $object | add-member Noteproperty ComputerName $_
                $object
            }

            $AllComputersCount = $AllComputers.count

            # Status user
            Write-Output " [*] - $AllComputersCount computers found in file."
        }

        # Perform UDP scanning of identified SQL Server instances on udp port 1434
        write-output " [*] Performing UDP scanning $AllComputersCount computers."
        $UDPInstances = $AllComputers | Where-Object ComputerName -notlike "" | Get-SQLInstanceScanUDPThreaded -Threads $Threads
        $UDPInstancesCount = $UDPInstances.count
        Write-Output " [*] - $UDPInstancesCount instances responded."
        $UDPInstances | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-UDPResponse.csv"

        # ------------------------------------------
        # Access Discovery
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] ACCESS DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Check if targeting all or just those that responded to UDP
        if($CheckAll){

            # Attempt to log into instances that found via SPNs
            Write-Output " [*] Attempting to log into $AllInstancesCount instances found via SPN query."
            $LoginAccess = $AllInstances | Get-SQLServerInfoThreaded -Threads $Threads
            $LoginAccessCount = $LoginAccess| measure-object | select count -ExpandProperty count 
            Write-Output " [*] - $LoginAccessCount could be logged into."
            $LoginAccess | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess.csv"    

        }else{

            # Attempt to log into instances that responded to UDP
            Write-Output " [*] Attempting to log into $UDPInstancesCount instances that responded to UDP scan."
            $LoginAccess = $UDPInstances | Get-SQLServerInfoThreaded -Threads $Threads
            $LoginAccessCount = $LoginAccess | measure-object | select count -ExpandProperty count 
            Write-Output " [*] - $LoginAccessCount could be logged into."
            $LoginAccess | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess.csv"
        } 
        
        # Add to findings
        If ($LoginAccessCount -gt 0){

            # Add finding for each accessible isntance
            $LoginAccess | 
            foreach{

            # Defined data for finding
            $aComputerName = $_.ComputerName
            $aInstance = $_.Instance
            $DomainName = $_.DomainName
            $ServiceName = $_.ServiceName
            $ServiceAccount = $_.ServiceAccount
            $AuthenticationMode = $_.AuthenticationMode
            $Clustered = $_.Clustered
            $SQLServerVersionNumber = $_.SQLServerVersionNumber
            $SQLServerMajorVersion = $_.SQLServerMajorVersion
            $SQLServerEdition = $_.SQLServerEdition
            $SQLServerServicePack = $_.SQLServerServicePack
            $OSArchitecture = $_.OSArchitecture
            $OsMachineType = $_.OsMachineType
            $OSVersionName = $_.OSVersionName
            $OsVersionNumber = $_.OsVersionNumber
            $Currentlogin = $_.Currentlogin
            $IsSysadmin = $_.IsSysadmin
            $ActiveSessions = $_.ActiveSessions                                

            # Define verification data object
            $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
DomainName: $DomainName
ServiceName: $ServiceName
ServiceAccount: $ServiceAccount
AuthenticationMode: $AuthenticationMode
Clustered: $Clustered
SQLServerVersionNumber: $SQLServerVersionNumber
SQLServerMajorVersion: $SQLServerMajorVersion
SQLServerEdition: $SQLServerEdition
SQLServerServicePack: $SQLServerServicePack
OSArchitecture: $OSArchitecture
OsMachineType: $OsMachineType
OSVersionName: $OSVersionName
OsVersionNumber: $OsVersionNumber
Currentlogin: $Currentlogin
IsSysadmin: $IsSysadmin
ActiveSessions: $ActiveSessions
"@

            # Define date/time
            $CurrentDate = Date

            # Add findings to the list
            $null = $AllFindings.Rows.Add("MAN:M:8c7437f9-080f-4ae3-95dc-08b86504a7b3",
                                         "Excessive Privileges - SQL Server Login",
                                         $aInstance,
                                         $aComputerName,         
                                         $StartTime,
                                         "The $Currentlogin user was able to log into the $aInstance SQL Server instance.",
                                         $ShareDetails)                
              }
        }else{
            Write-Output " [*] No SQL Server instances could be logged into"
            break
        }
        

        # Filter for instances with sysadmin privileges
        Write-Output " [*] Listing sysadmin access."
        $LoginAccessSysadmin = $LoginAccess | Where-Object IsSysadmin -like "Yes"
        $LoginAccessSysadminCount = $LoginAccessSysadmin | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $LoginAccessSysadminCount SQL Server instances provided sysadmin privileges."
        $LoginAccessSysadmin | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-LoginAccess-Sysadmin.csv"

        # Add to findings
        if($LoginAccessSysadminCount -gt 0){
                $LoginAccessSysadmin | 
                foreach{
                    $aComputerName = $_.ComputerName
                    $aInstance = $_.Instance
                    $DomainName = $_.DomainName
                    $ServiceName = $_.ServiceName
                    $ServiceAccount = $_.ServiceAccount
                    $AuthenticationMode = $_.AuthenticationMode
                    $Clustered = $_.Clustered
                    $SQLServerVersionNumber = $_.SQLServerVersionNumber
                    $SQLServerMajorVersion = $_.SQLServerMajorVersion
                    $SQLServerEdition = $_.SQLServerEdition
                    $SQLServerServicePack = $_.SQLServerServicePack
                    $OSArchitecture = $_.OSArchitecture
                    $OsMachineType = $_.OsMachineType
                    $OSVersionName = $_.OSVersionName
                    $OsVersionNumber = $_.OsVersionNumber
                    $Currentlogin = $_.Currentlogin
                    $IsSysadmin = $_.IsSysadmin
                    $ActiveSessions = $_.ActiveSessions                                

                # Define verification data
                $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
DomainName: $DomainName
ServiceName: $ServiceName
ServiceAccount: $ServiceAccount
AuthenticationMode: $AuthenticationMode
Clustered: $Clustered
SQLServerVersionNumber: $SQLServerVersionNumber
SQLServerMajorVersion: $SQLServerMajorVersion
SQLServerEdition: $SQLServerEdition
SQLServerServicePack: $SQLServerServicePack
OSArchitecture: $OSArchitecture
OsMachineType: $OsMachineType
OSVersionName: $OSVersionName
OsVersionNumber: $OsVersionNumber
Currentlogin: $Currentlogin
IsSysadmin: $IsSysadmin
ActiveSessions: $ActiveSessions
"@

                # Define date/time
                $CurrentDate = Date

                # Add findings to the list
                $null = $AllFindings.Rows.Add("MAN:M:e9b862c0-2729-450e-9d16-2a02074f9327",
                                     "Excessive Privileges - SQL Server Login - Sysadmin Role",
                                     $aInstance,
                                     $aComputerName,         
                                     $StartTime,
                                     "The $Currentlogin user was able to log into the $aInstance SQL Server instance.",
                                     $ShareDetails)
            }

        }

        # Attempt to obtain a list of role members from SQL Server instance (requrie sysadmin)
        Write-Output " [*] Attempting to grab role members from $LoginAccessCount instances."
        Write-Output " [*] - This usually requires special privileges"
        $RoleMembers = $LoginAccess | Get-SQLServerRoleMember
        $RoleMembersCount = $RoleMembers | measure-object | select count -ExpandProperty count
        Write-Output " [*] - $RoleMembersCount role members were found."
        $RoleMembers | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-RoleMembers.csv"

        # Filter for common explicit role assignments for Everyone, Builtin\Users, Authenticated Users, and Domain Users
         Write-Output " [*] Identifying excessive role memberships."
        $ExcessiveRoleMemberships = $RoleMembers |
        ForEach-Object{

            # Filter for broad groups
            if (($_.PrincipalName -eq "Everyone") -or ($_.PrincipalName -eq "BUILTIN\Users") -or ($_.PrincipalName -eq "Authenticated Users") -or ($_.PrincipalName -like "*Domain Users") )            
            {
                $_
            }            
        }
        $ExcessiveRoleMembershipsCount = $ExcessiveRoleMemberships | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $ExcessiveRoleMembershipsCount were found."
        $ExcessiveRoleMemberships | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-RoleMembers-Excessive.csv"
        
        # Add finding
        If($ExcessiveRoleMembershipsCount -gt 0){

            $ExcessiveRoleMemberships |
            Foreach {
                # Verification data
                $aComputerName = $_.ComputerName
                $aInstance = $_.Instance 
                $RolePrincipalId = $_.RolePrincipalId 
                $RolePrincipalName = $_.RolePrincipalName
                $PrincipalId = $_.PrincipalId
                $PrincipalName = $_.PrincipalName

                # Get date/time
                $CurrentDate = Date

                # Define Verification details
                $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance 
RolePrincipalId: $RolePrincipalId 
RolePrincipalName: $RolePrincipalName
PrincipalId: $PrincipalId
PrincipalName: $PrincipalName
"@

                # Add finding to list
                $null = $AllFindings.Rows.Add("MAN:M:afbd6d8b-36cb-4c99-bfc1-d3668b165c8b",
                                         "Excessive Privileges - SQL Server Login - Privileged Role",
                                         $aInstance,
                                         $aComputerName,         
                                         $StartTime,
                                         "On the $aInstance SQL Server instance, the $PrincipalName login was provided the $RolePrincipalName role. This should be reviewed to ensure it's not providing excessive privileges.",
                                         $ShareDetails)
           }
        }

        Write-Output " [*] Attempting to grab permission from $LoginAccessCount instances."
        Write-Output " [*] - This usually requires special privileges"
        $Permissions = $LoginAccess | Get-SQLServerPriv | where permissionname -NotLike "*connect*" | where granteename -notlike "*#*" | where granteename -notlike "*NT SERVICE*" | where granteename -notlike "*NT AUTHORITY\SYSTEM*" 
        $PermissionsCount = $Permissions | measure-object | select count -ExpandProperty count
        Write-Output " [*] - $PermissionsCount permissions were found."
        $Permissions | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-Permissions.csv"
        
        # Add finding
        if($PermissionsCount -gt 0){
            $Permissions | 
            Foreach {
            
                # Add fields
                $aComputerName = $_.ComputerName
                $GranteeName = $_.GranteeName
                $GrantorName = $_.GrantorName 
                $aInstance = $_.Instance
                $ObjectName = $_.ObjectName
                $ObjectType = $_.ObjectType 
                $PermissionClass = $_.PermissionClass
                $PermissionName = $_.PermissionName
                $PermissionState = $_.PermissionState

                # Create verification item
                $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
GranteeName: $GranteeName
GrantorName: $GrantorName 
ObjectName: $ObjectName
ObjectType: $ObjectType 
PermissionClass: $PermissionClass
PermissionName: $PermissionName
PermissionState: $PermissionState
"@

                # Add finding
                $null = $AllFindings.Rows.Add("MAN:M:4a9f4fbf-477e-430d-9ae1-a13f46ea591e",
                                         "Excessive Privileges - SQL Server Login - Permissions",
                                         $aInstance,
                                         $aComputerName,         
                                         $StartTime,
                                         "On the $aInstance SQL Server instance, the $PrincipalName login was provided the $PermissionName permission. This should be reviewed to ensure it's not providing excessive privileges.",
                                         $ShareDetails)
            }
        }

        # Create a list of share service accounts from the instance information
        if($TargetsFile)
        {
            Write-Output " [*] Shared service accounts will not be identified, because SPN informatin is required."            
        }else{
            Write-Output " [*] Identifying shared SQL Server service accounts."
            $SharedAccounts = $AllInstances | Group-Object DomainAccount | Sort-Object Count -Descending | Where Count -GT 2 |  Select Count, Name | Where-Object {($_.name -notlike "*$")}
            $SharedAccountsCount = $SharedAccounts |  Measure-Object | Select count -ExpandProperty count
            Write-Output " [*] - $SharedAccountsCount shared accounts were found."
            $SharedAccounts | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-SharedAccounts.csv"
        }

        # Add finding
        If($SharedAccountsCount -gt 0){

            # Foreach share account
            $SharedAccounts | 
            Foreach{
                
                $ShareAccountName = $_.Name
                $ShareAccountNameCount = $_.Count

                # Get a list of affected instances
                $AffectedInstances = $AllInstances | Where DomainAccount -like "$ShareAccountName"

                # Foreach affected instance add record
                $AffectedInstances| 
                Foreach{

                    # Get Data
                    $aComputerName = $_.ComputerName
                    $aInstance = $_.Instance
                    $Description = $_.Description
                    $DomainAccount = $_.DomainAccount 
                    $DomainAccountCn = $_.DomainAccountCn
                    $DomainAccountSid = $_.DomainAccountSid                    
                    $LastLogon = $_.LastLogon
                    $Service = $_.Service
                    $Spn = $_.Spn

                    # Make verification item
                    $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
Description: $Description
DomainAccount: $DomainAccount 
DomainAccountCn: $DomainAccountCn
DomainAccountSid: $DomainAccountSid
LastLogon: $LastLogon
Service: $Service
Spn: $Spn
"@

                    # Add Findings
                    $null = $AllFindings.Rows.Add("MAN:M:691129",
                                         "Account Management - Shared SQL Server Service Account",
                                         $aInstance,
                                         $aComputerName,         
                                         $StartTime,
                                         "The $aInstance instance's service is run using the account $DomainAccount. That account is used to run $ShareAccountNameCount instances.",
                                         $ShareDetails)                                   
                    
                }
            }
           
        }
        

        # Create a summary of the affected SQL Server versions
        Write-Output " [*] Creating a list of accessible SQL Server instance versions."
        $SQLServerVersions = $LoginAccess |  Group-Object SQLServerEdition | Sort-Object Count -Descending | Select Count, Name
        $SQLServerVersionsCount = $SQLServerVersions.count
        Write-Output " [*] - $SQLServerVersionsCount versions were found that could be logged into."
        $SQLServerVersions | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Instances-VersionSummary.csv"
                  
        # ------------------------------------------
        # Data Discovery: Database Targets
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] DATABASE TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Get a list of all accessible non-default databases from SQL Server instances
        Write-Output " [*] Querying for all non-default accessible databases."
        $Databases = $LoginAccess | Get-SQLDatabaseThreaded -NoDefaults -HasAccess
        $DatabasesCount = $Databases | Measure-Object | Select count -ExpandProperty count
        Write-Output " [*] - $DatabasesCount accessible non-default databases were found."
        $Databases | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases.csv"
        
        # Add finding
            $Databases | 
            Foreach {
            
                $aComputerName = $_.ComputerName
                $aInstance = $_.Instance
                $aDatabaseId = $_.DatabaseId
                $aDatabaseName = $_.DatabaseName
                $aDatabaseOwner = $_.DatabaseOwner
                $aOwnerIsSysadmin = $_.OwnerIsSysadmin
                $ais_trustworthy_on = $_.is_trustworthy_on
                $ais_db_chaining_on = $_.is_db_chaining_on
                $ais_broker_enabled = $_.is_broker_enabled
                $ais_encrypted = $_.is_encrypted
                $ais_read_only = $_.is_read_only
                $acreate_date = $_.create_date
                $arecovery_model_desc = $_.recovery_model_desc
                $aFileName = $_.FileName
                $aDbSizeMb = $_.DbSizeMb
                $ahas_dbaccess = $_.has_dbaccess

$ShareDetails =  @"
ComputerName: = $aComputerName
Instance: $aInstance
DatabaseId: $aDatabaseId
DatabaseName: $aDatabaseName
DatabaseOwner: $aDatabaseOwner
OwnerIsSysadmin: $aOwnerIsSysadmin
is_trustworthy_on: $ais_trustworthy_on
is_db_chaining_on: $ais_db_chaining_on
is_broker_enabled: $ais_broker_enabled
is_encrypted: $ais_encrypted
is_read_only: $a.is_read_only
create_date: $acreate_date
recovery_model_desc: $arecovery_model_desc
FileName: $aFileName
DbSizeMb: $aDbSizeMb
has_dbaccess: $ahas_dbaccess
"@
                # Get date/time
                $CurrentDate = Date

                # Add finding to list
                $null = $AllFindings.Rows.Add("MAN:M:40ffca5b-d8c9-4f36-9fff-6b56a4aaa2cb",
                                     "Excessive Privileges - SQL Server Login - Non Default Database",
                                     $aInstance,
                                     $aComputerName,         
                                     $StartTime,
                                     "On the $aInstance SQL Server instance, the $aDatabaseName database was found accessible.",
                                     $ShareDetails)                
            }

        # Filter for potential high value databases if transparent encryption is used
        Write-Output " [*] Filtering for databases using transparent encryption."
        $DatabasesEnc = $Databases | Where-Object {$_.is_encrypted -eq "TRUE"} 
        $DatabasesEncCount =  $DatabasesEnc| Measure-Object | Select count -ExpandProperty count
        Write-Output " [*] - $DatabasesEncCount databases were found using encryption."
        $DatabasesEnc | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-Encrypted.csv"

        # Define database name keywords to look for
        $DbNameKeyWords = @(    'ACH',
                                'finance',
                                'pci',
                                'card',
                                'chd',
                                'pos',
                                'enclave')

        # datatable to store stats
        $StatsDbName = new-object System.Data.DataTable 
        $StatsDbName.Columns.Add("keyword") | Out-Null
        $StatsDbName.Columns.Add("Count")   | Out-Null
             
        # Filter for potential high value databases based on keywords        
        $DbNameKeyWords | 
        Foreach{      
            $DbKeyword = $_
            Write-Output " [*] Filtering for databases with names that contain $DbKeyword "
            $DatabasesFound = $Databases | Where-Object {$_.DatabaseName -like "*$DbKeyword*"} 
            $DatabasesFoundCount = $DatabasesFound | Measure-Object | Select count -ExpandProperty count
            Write-Output " [*] - $DatabasesFoundCount database names contain $DbKeyword"
            $StatsDbName.Rows.Add("$DbKeyword","$DatabasesFoundCount") | Out-Null
            $DatabasesFound | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Databases-$DbKeyword.csv"
            $DatabasesFound | 
            Foreach {
            
                $aComputerName = $_.ComputerName
                $aInstance = $_.Instance
                $aDatabaseId = $_.DatabaseId
                $aDatabaseName = $_.DatabaseName
                $aDatabaseOwner = $_.DatabaseOwner
                $aOwnerIsSysadmin = $_.OwnerIsSysadmin
                $ais_trustworthy_on = $_.is_trustworthy_on
                $ais_db_chaining_on = $_.is_db_chaining_on
                $ais_broker_enabled = $_.is_broker_enabled
                $ais_encrypted = $_.is_encrypted
                $ais_read_only = $_.is_read_only
                $acreate_date = $_.create_date
                $arecovery_model_desc = $_.recovery_model_desc
                $aFileName = $_.FileName
                $aDbSizeMb = $_.DbSizeMb
                $ahas_dbaccess = $_.has_dbaccess

$ShareDetails =  @"
ComputerName: = $aComputerName
Instance: $aInstance
DatabaseId: $aDatabaseId
DatabaseName: $aDatabaseName
DatabaseOwner: $aDatabaseOwner
OwnerIsSysadmin: $aOwnerIsSysadmin
is_trustworthy_on: $ais_trustworthy_on
is_db_chaining_on: $ais_db_chaining_on
is_broker_enabled: $ais_broker_enabled
is_encrypted: $ais_encrypted
is_read_only: $a.is_read_only
create_date: $acreate_date
recovery_model_desc: $arecovery_model_desc
FileName: $aFileName
DbSizeMb: $aDbSizeMb
has_dbaccess: $ahas_dbaccess
"@
                # Get date/time
                $CurrentDate = Date

                # Add finding to list
                $null = $AllFindings.Rows.Add("MAN:M:abf35a11-a2da-401c-a23e-ab5584909633",
                                     "Excessive Privileges - SQL Server Login - Sensitive Database Name",
                                     $aInstance,
                                     $aComputerName,         
                                     $StartTime,
                                     "On the $aInstance SQL Server instance, the $aDatabaseName database was found accessible and it's name contains `"$DbKeyword`", which could indicate sensitive data exposure.",
                                     $ShareDetails)                
            }
        }

        # ------------------------------------------
        # Data Discovery: Sensitive Data Targets
        # ------------------------------------------

        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] SENSITIVE DATA TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Define table column name keywords to look for
        $ColumnNameKeyWords = @('ssn',
                                'card',
                                'credit',
                                'card')

        # datatable to store stats
        $StatsData = new-object System.Data.DataTable 
        $StatsData.Columns.Add("keyword") | Out-Null
        $StatsData.Columns.Add("Count")   | Out-Null

        # Search for the keyword in the table column names
        $ColumnNameKeyWords | 
        Foreach {

            $ColumnNameKeyWord = $_
            # Target keyword via column name
            Write-Output " [*] Search accessible non-default databases for table column names containing $ColumnNameKeyWord."
            $TblColumnKeywordMatches = $LoginAccess | Get-SQLColumnSampleDataThreaded -SampleSize 2 -NoDefaults -Threads $SampleThreads -Keywords "$ColumnNameKeyWord"
            $TblColumnKeywordMatchesCount = $TblColumnKeywordMatches | Measure-Object | select count -ExpandProperty count
            Write-Output " [*] - $TblColumnKeywordMatchesCount table columns found containing $ColumnNameKeyWord."
            $StatsData.Rows.Add("$ColumnNameKeyWord","$TblColumnKeywordMatchesCount") | out-null
            $TblColumnKeywordMatches | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Data-$ColumnNameKeyWord.csv"
        }

        if($TblColumnKeywordMatchesCount -gt 0){

            $TblColumnKeywordMatches |
            foreach{

                # Get data
                $aComputerName = $_.ComputerName
                $aInstance = $_.Instance
                $Database = $_.Database 
                $Schema = $_.Schema
                $Table = $_.Table
                $Column = $_.Column
                $Sample = $_.Sample
                $RowCount = $_.RowCount
                $ColumnPath = "$Database.$Schema.$Table.$Column"

                # Create verification item
                $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
Database: $Database 
Schema: $Schema
Table: $Table
Column: $Column
Sample: $Sample
RowCount: $RowCount
"@

                # Add record
                $null = $AllFindings.Rows.Add("MAN:M:abf35a11-a2da-401c-a23e-ab5584909633",
                                     "Excessive Privileges - SQL Server Login - Sensitive Data Column",
                                     $aInstance,
                                     $aComputerName,         
                                     $StartTime,
                                     "On the $aInstance SQL Server instance, the $ColumnPath column was found that may store sensitive data containing $RowCount rows.",
                                     $ShareDetails)  

            }
        }

        # ------------------------------------------
        # Data Discovery: Password Targets
        # ------------------------------------------
        
        Write-Output " [*] -------------------------------------------------------------"
        Write-Output " [*] PASSWORD TARGET DISCOVERY"
        Write-Output " [*] -------------------------------------------------------------"

        # Define table column name keywords to look for
        $ColumnNameKeyWords = @('password')

        # datatable to store stats
        $StatsPw = new-object System.Data.DataTable 
        $StatsPw.Columns.Add("keyword") | Out-Null
        $StatsPw.Columns.Add("Count")   | Out-Null

        # Search for the keyword in the table column names
        $ColumnNameKeyWords | 
        Foreach {

            $ColumnNameKeyWord = $_
            # Target keyword via column name
            Write-Output " [*] Search accessible non-default databases for table column names containing $ColumnNameKeyWord."
            $TblColumnKeywordMatches = $LoginAccess | Get-SQLColumnSampleDataThreaded -SampleSize 2 -NoDefaults -Threads $SampleThreads -Keywords "$ColumnNameKeyWord"
            $TblColumnKeywordMatchesCount = $TblColumnKeywordMatches | Measure-Object | select count -ExpandProperty count
            Write-Output " [*] - $TblColumnKeywordMatchesCount table columns found containing $ColumnNameKeyWord."
            $StatsPw.Rows.Add("$ColumnNameKeyWord","$TblColumnKeywordMatchesCount") | out-null
            $TblColumnKeywordMatches | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Data-$ColumnNameKeyWord.csv"
        }

        if($TblColumnKeywordMatchesCount -gt 0){

            $TblColumnKeywordMatches |
            foreach{

                # Get data
                $aComputerName = $_.ComputerName
                $aInstance = $_.Instance
                $Database = $_.Database 
                $Schema = $_.Schema
                $Table = $_.Table
                $Column = $_.Column
                $Sample = $_.Sample
                $RowCount = $_.RowCount
                $ColumnPath = "$Database.$Schema.$Table.$Column"

                # Create verification item
                $ShareDetails = @"
ComputerName: $aComputerName
Instance: $aInstance
Database: $Database 
Schema: $Schema
Table: $Table
Column: $Column
Sample: $Sample
RowCount: $RowCount
"@

                # Add record
                $null = $AllFindings.Rows.Add("MAN:M:77aca876-214f-4ad7-bac0-c340ee071517",
                                     "Excessive Privileges - SQL Server Login - Cleartext Password",
                                     $aInstance,
                                     $aComputerName,         
                                     $StartTime,
                                     "On the $aInstance SQL Server instance, the $ColumnPath column was found that may store cleartext passwords. It contains $RowCount rows.",
                                     $ShareDetails)  

            }
        }

        # Target passwords in agent jobs (requires privileges)
        Write-Output " [*] Search accessible non-default databases for agent source code containing PASSWORD."
        $AgentPasswords = $LoginAccess | Get-SQLAgentJob  -Keyword "password"
        $AgentPasswordsCount = $AgentPasswords.count
        Write-Output " [*] - $AgentPasswordsCount agent jobs containing PASSWORD."
        $AgentPasswords | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Passswords-AgentJobs.csv"

        # Target passwords in stored procedures (requires privileges)
        Write-Output " [*] Search accessible non-default databases for stored procedure source code containing PASSWORD."
        $SpPasswords = $LoginAccess | Get-SQLStoredProcedure  -Keyword "password"
        $SpPasswordsCount = $SpPasswords.count
        Write-Output " [*] - $SpPasswordsCount stored procedures containing PASSWORD."
        $SpPasswords | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Passswords-Procedures.csv"                                                             
   }

   End
   {
        # Get run time
        $EndTime = Get-Date
        $StopWatch.Stop()
        $RunTime = $StopWatch | Select-Object Elapsed -ExpandProperty Elapsed

        # ------------------------------------------
        # Console Report
        # ------------------------------------------

        # Generate summary console output
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  SQL SERVER HUNT SUMMARY REPORT                                  "        
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Scan Summary                                                   "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o Domain     : $TargetDomain"
        Write-Output "  o Start Time : $StartTime"
        Write-Output "  o Stop Time  : $EndTime"
        Write-Output "  o Run Time   : $RunTime"
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Instance Summary                                               "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $AllInstancesCount SQL Server instances found via SPN LDAP query."
        Write-Output "  o $UDPInstancesCount SQL Server instances responded to port 1434 UDP requests."    
        Write-Output "  "   
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Access Summary                                                 "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  "
        Write-Output "  Access:"
        Write-Output "  o $LoginAccessCount SQL Server instances could be logged into."
        Write-Output "  o $LoginAccessSysadminCount SQL Server instances provided sysadmin access."        
        Write-Output "  o $RoleMembersCount SQL Server role members were enumerated. *requires privileges"
        Write-Output "  o $ExcessiveRoleMembershipsCount excessive role assignments were identified."
        Write-Output "  o $SharedAccountsCount Shared SQL Server service accounts found."
        Write-Output "  "
        Write-Output "  Below are the top 5:"

        # Display top 5 most common service accounts
        $SqlServiceAccountTop5 = $SharedAccounts | Select-Object count,name -First 5
        $SqlServiceAccountTop5 |
        Foreach{
            
            $CurrentCount = $_.count
            $CurrentName = $_.name
            Write-Output "  o $CurrentCount $CurrentName"                                          
        } 
        
        Write-Output "  "
        Write-Output "  Below is a summary of the versions for the accessible instances:"

        # Display all SQL Server instance version counts
        $LoginAccess | Group-Object SQLServerEdition | Sort-Object count -Descending | Select-Object count,name |
        Foreach{
            
            $CurrentCount = $_.count
            $CurrentName = $_.name
            Write-Output "  o $CurrentCount $CurrentName"                                       
        } 

        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Database Summary                        "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  o $DatabasesCount accessible non-default databases were found."        
        Write-Output "  o $DatabasesEncCount databases were found configured with transparent encryption."       
        $StatsDbName | 
        foreach {
            $Keyword = $_.keyword
            $count = $_.count
            Write-Output "  o $count database names contain $Keyword."
        }
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Sensitive Data Access Summary                     "
        Write-Output "  ----------------------------------------------------------------"        
        $StatsData | 
        foreach {
            $Keyword = $_.keyword
            $count = $_.count
            Write-Output "  o $count sample rows were found for columns containing $Keyword."
        }
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"
        Write-Output "  Password Access Summary                               "
        Write-Output "  ----------------------------------------------------------------"        
        $StatsPw | 
        foreach {
            $Keyword = $_.keyword
            $count = $_.count
            Write-Output "  o $count sample rows were found for columns containing $Keyword."
        }
        Write-Output "  o $AgentPasswordsCount agent jobs potentially contain passwords. *requires sysadmin"
        Write-Output "  o $SpPasswordsCount stored procedures potentially contain passwords. *requires sysadmin"
        Write-Output "  "
        Write-Output "  ----------------------------------------------------------------"  

        # ------------------------------------------
        # HTML Report
        # ------------------------------------------
        
        $HTMLReport1 = @"        
        <HTML>
         <HEAD>
         </HEAD>
         <BODY>
            <H1>SQL SERVER HUNT SUMMARY REPORT</H1>
            <strong>Domain:</strong>$TargetDomain<Br>
			
			<H3>Scan Summary</H3>
			<ul>
				<li>Start Time: $StartTime</li>
				<li>End Time: $EndTime</li>
				<li>Run Time: $RunTime</li>
			</ul>
            
            <H3>Instance Summary</H3>
            
            <ul>
             <li>$AllInstancesCount SQL Server instances found via SPN LDAP query.</li>
             <li>$UDPInstancesCount SQL Server instances responded to port 1434 UDP requests.</li>        
            </ul>
            
            <H3>Access Summary</H3>
            
            <ul>
             <li>$LoginAccessCount SQL Server instances could be logged into.</li>
             <li>$LoginAccessSysadminCount SQL Server instances provided sysadmin access.</li>
             <li>$RoleMembersCount SQL Server role members were enumerated. *Requires privileges</li>             
             <li>$ExcessiveRoleMembershipsCount excessive role assignments were identified.</li>             
             <li>
                 $SharedAccountsCount Shared SQL Server service accounts found.<br>
                 Below are the top 5:
                 <ul>
"@
                                     
                # Display top 5 most common service accounts
                $SqlServiceAccountTop5 = $SharedAccounts | Select-Object count,name -First 5
                $HTMLReport2 = $SqlServiceAccountTop5 |
                Foreach{
            
                    $CurrentCount = $_.count
                    $CurrentName = $_.name
                    Write-Output "<li>$CurrentCount $CurrentName</li>"                                                         
                } 

        $HTMLReport3 = @"   
                </ul>
              </li>                       
              <li>
                Below is a summary of the versions for the accessible instances:
                <ul>
"@
                # Display all SQL Server instance version counts
                $HTMLReport4 = $LoginAccess | Group-Object SQLServerEdition | Sort-Object count -Descending | Select-Object count,name |
                Foreach{
            
                    $CurrentCount = $_.count
                    $CurrentName = $_.name
                    Write-Output "<li>$CurrentCount $CurrentName</li>"                                      
                }             

        # Generate stats html
	    $StatsDataHTML = ""
	    $StatsData | 
            foreach {
                $Keyword = $_.keyword
                $count = $_.count
                $StatsDataHTML = $StatsDataHTML + "<li>$count sample rows were found for columns containing $Keyword.</li>"
           
            }

            # Display pw status
	    $StatsPwHTML = ""
	    $StatsPw | 
            foreach {
                $Keyword = $_.keyword
                $count = $_.count
                $StatsPwHTML = $StatsPwHTML + "<li>$count sample rows were found for columns containing $Keyword.</li>"
           
            }

            # Display database status
	    $StatsDbNameHTML = ""
	    $StatsDbName | 
            foreach {
                $Keyword = $_.keyword
                $count = $_.count
                $StatsDbNameHTML = $StatsDbNameHTML + "<li>$count database names contain $Keyword.</li>"
           
            }



        # Add to html
        $HTMLReport5 = @" 
                </ul>
              </li>
            </ul>

            <H3>Database Summary</H3>
            
            <ul>
             <li>$DatabasesCount accessible non-default databases were found.</li>
             <li>$DatabasesEncCount databases were found configured with transparent encryption.</li>             
             $StatsDbNameHTML
            </ul>           

            <H3>Sensitive Data Access Summary</H3>
            
            <ul>
             $StatsDataHTML         
            </ul>

            <H3>Password Access Summary</H3>
            
            <ul>
             $StatsPwHTML
             <li>$AgentPasswordsCount agent jobs potentially contain passwords. *Privileges required</li>
             <li>$SpPasswordsCount stored procedures potentially contain passwords. *Privileges requried</li>             
            </ul>           
         </BODY>
        </HTML>   
"@
        $HTMLReport = $HTMLReport1 + $HTMLReport2 + $HTMLReport3 + $HTMLReport4 + $HTMLReport5
        Write-Output " [*] Saving results to $OutputDirectory\$TargetDomain-SQLServer-Summary-Report.html"        
        $HTMLReport | Out-File "$OutputDirectory\$TargetDomain-SQLServer-Summary-Report.html"

        # ----------------------------------------------------
        # Correlate FQDN and hostnames for export
        # Get a list of all hostnames that are not fqdn
        # ----------------------------------------------------

        # Get unique non fqdn host names
        $HostnamesUnique = $AllFindings | where AssetName -notlike "*.*"  | Select -Unique 

        # Check each name for FQDN match
        $HostnameMatches = $HostnamesUnique |
        Foreach{

	        # Get hostname      
	        $AssetName = $_.AssetName

            # Check if a FQDN exists for the hostname
            # If match, add to the list
	        $AllFindings | where AssetName -like "*.*" |
	        Foreach {

		        $FQDN = $_.AssetName

		        # Compare hostname to fqdn
		        If($FQDN -like "$AssetName.*.*"){
			
                    $object = new-object psobject
                    $object | Add-Member -MemberType NoteProperty -Name 'Hostname' -Value $AssetName
                    $object | Add-Member -MemberType NoteProperty -Name 'FQDN' -Value $FQDN				
                    $object
		        }
	        }	    
        }

        # Unique matches
        $HostnameMatchesUnique = $HostnameMatches | select -Unique

        # Update records
        $AllFindingsClean = $AllFindings | Select MasterFindingSourceIdentifier,InstanceName,AssetName,IssueFirstFoundDate,VerificationCaption01,VerificationText01 | 
        Foreach{

            # Get fields
	        $nMasterFindingSourceIdentifier = $_.MasterFindingSourceIdentifier
	        $nInstanceName = $_.InstanceName
	        $nAssetName = $_.AssetName	
	        $nnIssueFirstFoundDate = $_.IssueFirstFoundDate
	        $nVerificationCaption01 = $_.VerificationCaption01
	        $nVerificationText01 = $_.VerificationText01

            # Check if the hostname needs to be updated
            if($nAssetName -notlike "*.*"){
            
                # check for match
                $ConfirmedMatch = $HostnameMatchesUnique | where hostname -eq "$assetname" 
                $ConfirmedMatchCount =  $ConfirmedMatch | measure-object | select count -ExpandProperty count

                if($ConfirmedMatchCount -gt 0){

                    # Updated hostname
                    $NewFQDN = $ConfirmedMatch | select fqdn -ExpandProperty fqdn -first 1

                    # Updated instance in verification
                    $VercapUpdate = $nVerificationCaption01 -replace("$nAssetName","$NewFQDN")
                    $VertxtUpdate = $nVerificationText01 -replace("$nAssetName","$NewFQDN")

                    # return record with updated assetname and instance
                    $object = new-object psobject
                    $object | Add-Member -MemberType NoteProperty -Name $rMasterFindingId -Value $nMasterFindingSourceIdentifier
                    $object | Add-Member -MemberType NoteProperty -Name $rFindingName -Value $nInstanceName	
                    $object | Add-Member -MemberType NoteProperty -Name $rAssetName -Value $NewFQDN
                    if(-not $Nova){$object | Add-Member -MemberType NoteProperty -Name 'IssueFirstFoundDate' -Value $nIssueFirstFoundDate}		
                    $object | Add-Member -MemberType NoteProperty -Name 'VerificationCaption01' -Value $nVerificationCaption01	
                    $object | Add-Member -MemberType NoteProperty -Name 'VerificationText01' -Value "<pre><code>$nVerificationText01</code></pre>"	
                    $object

                }else{
                    
                    # return hostname record with no update
                    $object = new-object psobject
                    $object | Add-Member -MemberType NoteProperty -Name $rMasterFindingId -Value $nMasterFindingSourceIdentifier
                    $object | Add-Member -MemberType NoteProperty -Name $rFindingName -Value $nInstanceName	
                    $object | Add-Member -MemberType NoteProperty -Name $rAssetName -Value $nAssetName
                    if(-not $Nova){$object | Add-Member -MemberType NoteProperty -Name 'IssueFirstFoundDate' -Value $nIssueFirstFoundDate}		
                    $object | Add-Member -MemberType NoteProperty -Name 'VerificationCaption01' -Value $nVerificationCaption01	
                    $object | Add-Member -MemberType NoteProperty -Name 'VerificationText01' -Value "<pre><code>$nVerificationText01</code></pre>"	
                    $object
                }

            }else{

                # return fqdn record with no update
                $object = new-object psobject
                $object | Add-Member -MemberType NoteProperty -Name $rMasterFindingId -Value $nMasterFindingSourceIdentifier
                $object | Add-Member -MemberType NoteProperty -Name $rFindingName -Value $nInstanceName	
                $object | Add-Member -MemberType NoteProperty -Name $rAssetName -Value $nAssetName
                if(-not $Nova){$object | Add-Member -MemberType NoteProperty -Name 'IssueFirstFoundDate' -Value $nIssueFirstFoundDate}		
                $object | Add-Member -MemberType NoteProperty -Name 'VerificationCaption01' -Value $nVerificationCaption01	
                $object | Add-Member -MemberType NoteProperty -Name 'VerificationText01' -Value "<pre><code>$nVerificationText01</code></pre>"	
                $object

            }
        }

    # Save export file
    $AllFindingsClean | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-SQLServer-Findings-Export.csv" 
   }
}	