#--------------------------------------
# Function: Invoke-HuntSMBShares
#--------------------------------------
# Author: Scott Sutherland, 2022 NetSPI
# License: 3-clause BSD
# Version: v1.4.22
# References: This script includes code taken and modified from the open source projects PowerView, Invoke-Ping, and Invoke-Parrell. 
# TODO: Add export summary csv. Domain, affected shares by type. High risk read, high risk write.
function Invoke-HuntSMBShares
{    
	<#
            .SYNOPSIS
            This function can be used to inventory to SMB shares on the current Active Directory domain and identify potentially high risk exposures.  
			It will automatically generate csv files and html summary report.
            .PARAMETER Threads
            Number of concurrent tasks to run at once.
            .PARAMETER Output Directory
            File path where all csv and html report will be exported.
            .EXAMPLE
			PS C:\temp\test> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\temp\test -DomainController 10.1.1.1 -Credential domain\user    
            .EXAMPLE
			PS C:\temp\test> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\temp\test -DomainController 10.1.1.1 -Username domain\user -Password password            
            .EXAMPLE
			PS C:\temp\test> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\temp\test
			  ---------------------------------------------------------------
			| Invoke-HuntSMBShares                                          |
			  ---------------------------------------------------------------
			| This function automates the following tasks:                  |
			|                                                               |
			| o Determine current computer's domain                         |
			| o Enumerate domain computers                                  |
			| o Filter for computers that respond to ping reqeusts          |
			| o Filter for computers that have TCP 445 open and accessible  |
			| o Enumerate SMB shares                                        |
			| o Enumerate SMB share permissions                             |
			| o Identify shares with potentially excessive privielges       |
			| o Identify shares that provide write access                   |
			| o Identify shares thare are high risk                         |
			| o Identify common share names with more than 5 instances      |
			|                                                               |
			  ---------------------------------------------------------------
			| Note: This can take hours to run in large environments.       |
			  ---------------------------------------------------------------
			[*] Start time: 08/18/2020 10:16:35
			[*] All results will be written to the directory c:\temp\test
			[*] Performing LDAP query for computers associated with the my.test.domain.com domain
			[*] - 10358 computers found
			[*] - Saving results to c:\temp\test\my.test.domain.com-Domain-Computers.csv
			[*] Pinging 10358 computers
			[*] - 5018 computers responded to ping requests.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Domain-Computers-Pingable.csv
			[*] Checking if TCP Port 445 is open on 5018 computers
			[*] - 4900 computers have TCP port 445 open.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Domain-Computers-Open445.csv
			[*] Getting a list of SMB shares from 4900 computers
			[*] - 10866 SMB shares were found.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-All.csv
			[*] Getting share permissions from 10866 SMB shares
			[*] - 13399 share permissions were enumerated.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-All-ACL.csv
			[*] Identifying potentially excessive share permissions
			[*] - 930 potentially excessive privileges were found across 170 systems.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-Excessive-Privileges.csv
			[*] - 131 shares can be written to across 87 systems.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-Excessive-Privileges-Write.csv
			[*] - 378 that are considered high risk across 75 systems.
			[*] - Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-Excessive-Privileges-HighRisk.csv
			[*] Generating summary data
			[*] Saving results to c:\temp\test\my.test.domain.com-Shares-Inventory-Common-Names.csv
			[*] - 274 of 325 ( %)shares are have more than 5 duplicates
			[*] Results written to c:\temp\test
			[*] 
			[*] -----------------------------------------------
			[*] Get-ShareInventory Summary Report
			[*] -----------------------------------------------
			[*] Domain: my.test.domain.com
			[*] Start time: 08/18/2020 10:16:35
			[*] End time: 08/18/2020 11:36:22
			[*] Run time: 01:19:47.0152660
			[*] 
			[*] Computer Summary
			[*] - 10358 domain computers found.
			[*] - 5018 domain computers responded to ping.
			[*] - 4900 domain computers had TCP port 445 accessible.
			[*] 
			[*] Share Summary
			[*] - 10866 shares were found.
			[*] - 930 potentially excessive privileges were found across 170 systems.
			[*] - 131 shares can be written to across 87 systems.
			[*] - 378 shares are considered high risk across 75 systems.
			[*] - 41 sharenames were discovered with more than 5 instances
			[*] - The 5 most common share names are:
			[*]   - 75 Users
			[*]   - 75 C$
			[*]   - 75 ADMIN$
			[*]   - 43 D$
			[*]   - 6 SYSVOL
			[*] -----------------------------------------------

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
        HelpMessage = 'Credentials to use when connecting to a Domain Controller. For computer lookup.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against. For computer lookup.')]
        [string]$DomainController,
        
        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of threads to process at once.')]
        [int]$Threads = 100,

        [Parameter(Mandatory = $true,
        HelpMessage = 'Directory to output files to.')]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Creat exported csv for import into other tools.')]
        [switch]$ExportFindings,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Number of items to sample for summary report.')]
        [int]$SampleSum = 5,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Runspace time out.')]
        [int]$RunSpaceTimeOut = 5
    )
	
    
    Begin
    {
        $TheVersion = "1.3.33"
        Write-Output "  ---------------------------------------------------------------" 
        Write-Output " | Invoke-HuntSMBShares                                          |"
        Write-Output "  ---------------------------------------------------------------"         
        Write-Output " | This function automates the following tasks:                  |"
        Write-Output " |                                                               |"
        Write-Output " | o Determine current computer's domain                         |"
        Write-Output " | o Enumerate domain computers                                  |"
        Write-Output " | o Filter for computers that respond to ping reqeusts          |"
        Write-Output " | o Filter for computers that have TCP 445 open and accessible  |"
        Write-Output " | o Enumerate SMB shares                                        |"
        Write-Output " | o Enumerate SMB share permissions                             |"
        Write-Output " | o Identify shares with potentially excessive privielges       |"
        Write-Output " | o Identify shares that provide write access                   |"                     
        Write-Output " | o Identify shares thare are high risk                         |"
        Write-Output " | o Identify common share names with more that 5 instances      |"
        Write-Output " |                                                               |"
        Write-Output "  ---------------------------------------------------------------"  
        Write-Output " | Note: This can take hours to run in large environments.       |"
        Write-Output "  ---------------------------------------------------------------"

        # Get start time
        $StartTime = Get-Date
        Write-Output " [*] Start time: $StartTime"
        $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
        
        # Set variables
        $GlobalThreadCount = $Threads

        Write-Output " [*] All results will be written to the directory $OutputDirectory"



        # ----------------------------------------------------------------------
        # Enumerate domain computers 
        # ----------------------------------------------------------------------

        # Set target domain        
        $DCRecord = Get-LdapQuery -LdapFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -DomainController $DomainController -Username $username -Password $Password -Credential $Credential | select -first 1 | select properties -expand properties -ErrorAction SilentlyContinue
        [string]$DCHostname = $DCRecord.dnshostname
        [string]$DCCn = $DCRecord.cn
        [string]$TargetDomain = $DCHostname -replace ("$DCCn\.","") 
                
        if($DCHostname)
        {
            Write-Output " [*] Successful connection to domain controller: $DCHostname"             
        }else{
            Write-Output " [*] There appears to have been an error connecting to the domain controller."
            Write-Output " [*] Aborting."
            break
        }           

        # Status user
        Write-Output " [*] Performing LDAP query for computers associated with the $TargetDomain domain"

        # Get domain computers        
        $DomainComputersRecord = Get-LdapQuery -LdapFilter "(objectCategory=Computer)" -DomainController $DomainController -Username $username -Password $Password
        $DomainComputers = $DomainComputersRecord | 
        foreach{
                
            $DnsHostName = [string]$_.Properties['dnshostname']
            if($DnsHostName -notlike ""){
                $object = New-Object psobject
                $Object | Add-Member Noteproperty ComputerName $DnsHostName
                $Object      
            }
        }

        # Status user
        $ComputerCount = $DomainComputers.count
        Write-Output " [*] - $ComputerCount computers found"

        # Save results
        Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Domain-Computers.csv"
        $DomainComputers | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Domain-Computers.csv"
        $null = Convert-DataTableToHtmlTable -DataTable $DomainComputers -Outfile "$OutputDirectory\$TargetDomain-Domain-Computers.html" -Title "Domain Computers" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain."
        $DomainComputersFile = "$TargetDomain-Domain-Computers.csv"
        $DomainComputersFileH = "$TargetDomain-Domain-Computers.html"

        # ----------------------------------------------------------------------
        # Identify computers that respond to ping reqeusts
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Pinging $ComputerCount computers"

        # Ping computerss
        $PingResults = $DomainComputers | Invoke-Ping -Throttle $GlobalThreadCount

        # select computers that respond
        $ComputersPingable = $PingResults |
        foreach {

            $computername = $_.address
            $status = $_.status
            if($status -like "Responding"){
                $object = new-object psobject            
                $Object | add-member Noteproperty ComputerName $computername
                $Object | add-member Noteproperty status $status
                $Object
            }
        }

        # Status user
        $ComputerPingableCount = $ComputersPingable.count
        Write-Output " [*] - $ComputerPingableCount computers responded to ping requests."
        
        # Stop if no hosts are accessible
        If ($ComputerPingableCount -eq 0)
        {
            Write-Output " [*] - Aborting."
            break
        }

        # Save results
        Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Domain-Computers-Pingable.csv"
        $ComputersPingable | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Domain-Computers-Pingable.csv"
        $null = Convert-DataTableToHtmlTable -DataTable $ComputersPingable -Outfile "$OutputDirectory\$TargetDomain-Domain-Computers-Pingable.html" -Title "Domain Computers: Ping Response" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain that responded to ping requests."
        $ComputersPingableFile = "$TargetDomain-Domain-Computers-Pingable.csv"
        $ComputersPingableFileH =  "$TargetDomain-Domain-Computers-Pingable.html"

        # ----------------------------------------------------------------------
        # Identify computers that have TCP 445 open and accessible
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Checking if TCP Port 445 is open on $ComputerPingableCount computers"

        # Get clean list of pingable computers
        $ComputersPingableClean = $ComputersPingable | Select-Object ComputerName

        # Create script block to port scan tcp 445
        $MyScriptBlock = {
                $ComputerName = $_.ComputerName
                try{                      
                    $Socket = New-Object System.Net.Sockets.TcpClient($ComputerName,"445")
                    
                    if($Socket.Connected)
                    {
                        $Status = "Open"             
                        $Socket.Close()
                    }
                    else 
                    {
                        $Status = "Closed"    
                    }
                }
                catch{
                    $Status = "Closed"
                }   

                if($Status -eq "Open")
                {            
                    $object = new-object psobject            
                    $Object | add-member Noteproperty ComputerName $computername
                    $Object | add-member Noteproperty 445status $status
                    $Object                            
                }
        }
           
        # Perform port scan of tcp 445 threaded
        $Computers445Open = $ComputersPingableClean | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $GlobalThreadCount -RunspaceTimeout $RunSpaceTimeOut -ErrorAction SilentlyContinue

        # Status user
        $Computers445OpenCount = $Computers445Open.count
        Write-Output " [*] - $Computers445OpenCount computers have TCP port 445 open."
        
         
        # Stop if no ports are accessible
        If ($Computers445OpenCount -eq 0)
        {
            Write-Output " [*] - Aborting."
            break
        }

        # Save results
        Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Domain-Computers-Open445.csv"        
        $Computers445Open | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Domain-Computers-Open445.csv"
        $null = Convert-DataTableToHtmlTable -DataTable $Computers445Open -Outfile "$OutputDirectory\$TargetDomain-Domain-Computers-Open445.html" -Title "Domain Computers: Port 445 Open" -Description "This page shows the domain computers for the $TargetDomain Active Directory domain with port 445 open."
        $Computers445OpenFile = "$TargetDomain-Domain-Computers-Open445.csv"
        $Computers445OpenFileH ="$TargetDomain-Domain-Computers-Open445.html"

        # ----------------------------------------------------------------------
        # Enumerate computer SMB shares
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Getting a list of SMB shares from $Computers445OpenCount computers"

        # Create script block to query for SMB shares
        $MyScriptBlock = { 
            Get-MySMBShare -ComputerName $_.ComputerName
        }

        # Get smb shares threaded
        $AllSMBShares = $Computers445Open | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $GlobalThreadCount -RunspaceTimeout $RunSpaceTimeOut -ErrorAction SilentlyContinue

        # Computer computers with shares
        $AllComputersWithShares = $AllSMBShares | Select-Object ComputerName -Unique
        $AllComputersWithSharesCount =  $AllComputersWithShares.count

        # Status user
        $AllSMBSharesCount = $AllSMBShares.count
        Write-Output " [*] - $AllSMBSharesCount SMB shares were found."
        
        # Stop if no shares
        If ($AllSMBSharesCount -eq 0)
        {
            Write-Output " [*] - Aborting."
            break
        }

        # Save results
        Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-All.csv"
        $AllSMBShares | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-All.csv"
        $null = Convert-DataTableToHtmlTable -DataTable $AllSMBShares -Outfile "$OutputDirectory\$TargetDomain-Shares-Inventory-All.html" -Title "Domain Shares" -Description "This page shows the all enumerated shares for the $TargetDomain Active Directory domain."
        $AllSMBSharesFile = "$TargetDomain-Shares-Inventory-All.csv"
        $AllSMBSharesFileH = "$TargetDomain-Shares-Inventory-All.html"

        # ----------------------------------------------------------------------
        # Enumerate computer SMB share permissions 
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Getting share permissions from $AllSMBSharesCount SMB shares"

        # Create script block to query for SMB permissions
        $MyScriptBlock = {     

            $CurrentShareName = $_.ShareName
            $CurrentComputerName = $_.ComputerName
            $CurrentIP = $_.IpAddress
            $ShareDescription = $_.ShareDesc
            $Sharetype = $_.sharetype
            $Shareaccess = $_.shareaccess
            
             if($CurrentComputerName -eq ""){
                 $TargetAsset = $CurrentIP    
             }else{
                 $TargetAsset = $CurrentComputerName
             }

             $currentaacl = Get-PathAcl "\\$TargetAsset\$CurrentShareName" -ErrorAction SilentlyContinue
             $currentaacl |
                foreach{
                        
                      # Get file listing
                      $FullFileList = Get-ChildItem -Path "\\$TargetAsset\$CurrentShareName"

                      # Get file count
                      $FileCount = $FullFileList.Count 

                      # Get top 5 files list
                      $FileList = $FullFileList | Select-Object Name -ExpandProperty Name | Out-String

                      # Get File listing hash
                      $FileListGroup = Get-FolderGroupMd5 -FolderList $FileList
                      $FileListGroup

                      # Last modified date
                      $TargetPath = $_.Path
                      $LastModifiedDate = Get-Item "\\$TargetAsset\$CurrentShareName" -ErrorAction SilentlyContinue | Select-Object LastWriteTime -ExpandProperty LastWriteTime

                      $aclObject = new-object psobject            
                      $aclObject | add-member  Noteproperty ComputerName         $CurrentComputerName
                      $aclObject | add-member  Noteproperty IpAddress            $CurrentIP
                      $aclObject | add-member  Noteproperty ShareName            $CurrentShareName
                      $aclObject | add-member  Noteproperty SharePath            $_.Path
                      $aclObject | add-member  Noteproperty ShareDescription     $ShareDescription
                      $aclObject | add-member  Noteproperty ShareOwner           $_.PathOwner
                      $aclObject | add-member  Noteproperty ShareType            $ShareType
                      $aclObject | add-member  Noteproperty ShareAccess          $ShareAccess
                      $aclObject | add-member  Noteproperty FileSystemRights     $_.FileSystemRights
                      $aclObject | add-member  Noteproperty IdentityReference    $_.IdentityReference
                      $aclObject | add-member  Noteproperty IdentitySID          $_.IdentitySID
                      $aclObject | add-member  Noteproperty AccessControlType    $_.AccessControlType
                      $aclObject | add-member  Noteproperty LastModifiedDate     $LastModifiedDate
                      $aclObject | add-member  Noteproperty FileCount            $FileCount
                      $aclObject | add-member  Noteproperty FileList             $FileList
                      $aclObject | add-member  Noteproperty FileListGroup        $FileListGroup
                      $aclObject                             
                }
         }   

        # Get SMB permissions threaded
        $ShareACLs = $AllSMBShares | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $GlobalThreadCount -RunspaceTimeout $RunSpaceTimeOut -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue 

        # Status user
        $ShareACLsCount = $ShareACLs.count
        Write-Output " [*] - $ShareACLsCount share permissions were enumerated."       
        
        # Stop if no shares ACLs were enumerated
        If ($ShareACLsCount -eq 0)
        {
            Write-Output " [*] - Aborting."
            break
        }

        # Save results
        Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-All-ACL.csv"
        $ShareACLs | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-All-ACL.csv"        
        $ShareACLsFile = "$OutputDirectory\$TargetDomain-Shares-Inventory-All-ACL.csv"
        # ----------------------------------------------------------------------
        # Get potentially excessive share permissions 
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Identifying potentially excessive share permissions"


        # Check for share that provide read/write access to common user groups
        $ExcessiveSharePrivs = foreach ($line in $ShareACLs){
            
            # Filter for basic user ACLs
            if (($line.IdentityReference -eq "Everyone") -or ($line.IdentityReference -eq "BUILTIN\Users") -or ($line.IdentityReference -eq "Authenticated Users") -or ($line.IdentityReference -like "*Domain Users*") ){
                
                if($line.ShareAccess -like "Yes"){

                    if(($line.ShareName -notlike "print$") -and ($line.ShareName -notlike "prnproc$") -and ($line.ShareName -notlike "*printer*") -and ($line.ShareName -notlike "netlogon") -and ($line.ShareName -notlike "sysvol"))
                    {
                        $line                        
                    }
                }
            }
        } 

        # Status user
        $ExcessiveAclCount = $ExcessiveSharePrivs.count
        $ExcessiveShares = $ExcessiveSharePrivs | Select-Object ComputerName,ShareName -unique
        $ExcessiveSharesCount = $ExcessiveShares.count
        $ExcessiveSharePrivsCount = $ExcessiveSharePrivs.count
        $ComputerWithExcessive = $ExcessiveSharePrivs | Select-Object ComputerName -Unique | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $ExcessiveSharePrivsCount potentially excessive privileges were found across $ComputerWithExcessive systems."

        # Save results
        if($ExcessiveSharesCount -ne 0){
            Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges.csv"            
            $ExcessiveSharePrivs | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges.csv"              
        }else{
            break
        }

        $ExcessiveSharePrivsFile = "$TargetDomain-Shares-Inventory-Excessive-Privileges.csv"

        # ----------------------------------------------------------------------
        # Identify shares that provide read access
        # ----------------------------------------------------------------------

        # Get shares that provide read access
        $SharesWithread = $ExcessiveSharePrivs | 
        Foreach {

            if(($_.FileSystemRights -like "*read*"))
            {
                $_ # out to file
            }
        }
                
        # Status user
        $AclWithReadCount = $SharesWithread.count
        $SharesWithReadCount = $SharesWithread | Select-Object SharePath -Unique | Measure-Object | select count -ExpandProperty count
        $ComputerWithReadCount = $SharesWithread | Select-Object ComputerName -Unique | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $SharesWithReadCount shares can be written to across $ComputerWithReadCount systems."

        # Save results
        if($SharesWithReadCount -ne 0){
            Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Read.csv"
            $SharesWithRead | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Read.csv"               
        }

        $SharesWithReadFile = "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Read.csv"

        # ----------------------------------------------------------------------
        # Identify shares that provide write access
        # ----------------------------------------------------------------------

        # Get shares that provide write access
        $SharesWithWrite = $ExcessiveSharePrivs | 
        Foreach {

            if(($_.FileSystemRights -like "*GenericAll*") -or ($_.FileSystemRights -like "*Write*"))
            {
                $_ # out to file
            }
        }
                
        # Status user
        $AclWithWriteCount = $SharesWithWrite | Measure-Object | select count -ExpandProperty count
        $SharesWithWriteCount = $SharesWithWrite | Select-Object SharePath -Unique | Measure-Object | select count -ExpandProperty count
        $ComputerWithWriteCount = $SharesWithWrite | Select-Object ComputerName -Unique | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $SharesWithWriteCount shares can be written to across $ComputerWithWriteCount systems."          

        # Save results
        if($SharesWithWriteCount -ne 0){
            Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Write.csv"
            $SharesWithWrite | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Write.csv"            
        }

        $SharesWithWriteFile = "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-Write.csv"

        # ----------------------------------------------------------------------
        # Identify shares that are non-default
        # ----------------------------------------------------------------------

        # Get high risk share access
        $SharesNonDefault = $ShareACLs | 
        Foreach {

            if(($_.ShareName -notlike 'admin$') -or ($_.ShareName -notlike 'c$') -or ($_.ShareName -notlike 'd$') -or ($_.ShareName -notlike 'e$') -or ($_.ShareName -notlike 'f$'))
            {
                $_ # out to file
            }
        }

        # Status user
        $AclNonDefaultCount = $SharesNonDefault.count
        $SharesNonDefaultCount = $SharesNonDefault | Select-Object SharePath -Unique | Measure-Object | select count -ExpandProperty count
        $ComputerwithNonDefaultCount = $SharesNonDefault | Select-Object ComputerName -Unique | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $SharesNonDefaultCount that are considered high risk across $ComputerwithNonDefaultCount systems."

        # Save results
        if($SharesNonDefaultCount-ne 0){
            Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-NonDefault.csv"
            $SharesNonDefault | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-NonDefault.csv"           
        }

        $SharesNonDefaultFile = "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-NonDefault.csv"

        # ----------------------------------------------------------------------
        # Identify shares that are high risk
        # ----------------------------------------------------------------------

        # Get high risk share access
        $SharesHighRisk = $ExcessiveSharePrivs | 
        Foreach {

            if(($_.ShareName -like 'c$') -or ($_.ShareName -like 'admin$') -or ($_.ShareName -like "*wwwroot*") -or ($_.ShareName -like "*inetpub*") -or ($_.ShareName -like 'c') -or ($_.ShareName -like 'c_share'))
            {
                $_ # out to file
            }
        }

        # Status user
        $AclHighRiskCount = $SharesHighRisk.count
        $SharesHighRiskCount = $SharesHighRisk | Select-Object SharePath -Unique | Measure-Object | select count -ExpandProperty count
        $ComputerwithHighRisk = $SharesHighRisk | Select-Object ComputerName -Unique | Measure-Object | select count -ExpandProperty count
        Write-Output " [*] - $SharesHighRiskCount that are considered high risk across $ComputerwithHighRisk systems."

        # Save results
        if($SharesHighRiskCount -ne 0){
            Write-Output " [*] - Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-HighRisk.csv"
            $SharesHighRisk | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-HighRisk.csv"            
        }

        $SharesHighRiskFile = "$OutputDirectory\$TargetDomain-Shares-Inventory-Excessive-Privileges-HighRisk.csv"

        # ----------------------------------------------------------------------
        # Identify common excessive share owners
        # ----------------------------------------------------------------------
        
        # Get share owner list
        $CommonShareOwners = $ExcessiveSharePrivs | Select SharePath,ShareOwner -Unique |
        Select-Object ShareOwner | 
        <#
        where ShareOwner -notlike "BUILTIN\Administrators" |
        where ShareOwner -notlike "NT AUTHORITY\SYSTEM" |
        where ShareOwner -notlike "NT SERVICE\TrustedInstaller" |
        #>
        Group-Object ShareOwner |
        Sort-Object ShareOwner | 
        Select-Object count,name |
        Sort-Object Count -Descending

        # Save list
        $CommonShareOwners | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Common-Owners.csv"
        $CommonShareOwnersCount = $CommonShareOwners | measure | select count -ExpandProperty count

        # Get top  5
        $CommonShareOwnersTop5 = $CommonShareOwners | Select-Object count,name -First $SampleSum 

        # ----------------------------------------------------------------------
        # Identify common excessive share groups (group by file list)
        # ----------------------------------------------------------------------
        
        # Get share owner list
        $CommonShareFileGroup = $ExcessiveSharePrivs | 
        Select-Object FileListGroup | 
        Group-Object FileListGroup| 
        Select-Object count,name |
        Sort-Object Count -Descending

        # Save list
        $CommonShareFileGroup | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Common-FileGroups.csv"
        $CommonShareFileGroupCount = $CommonShareFileGroup.count 

        # Get top  5
        $CommonShareFileGroupTop5 = $CommonShareFileGroup | Select-Object count,name,filecount -First $SampleSum 

        # ----------------------------------------------------------------------
        # Identify common share names
        # ----------------------------------------------------------------------

        # Status user
        Write-Output " [*] Generating summary data"
        Write-Output " [*] Saving results to $OutputDirectory\$TargetDomain-Shares-Inventory-Common-Names.csv"
        $CommonShareNames = $ExcessiveSharePrivs | Select-Object ComputerName,ShareName -Unique | Group-Object ShareName |Sort Count -Descending | select count,name | 
        foreach{
            if( ($_.name -ne 'SYSVOL') -and ($_.name -ne 'NETLOGON'))
            {
                $_                
            }
        }
        
        $CommonShareNames | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Shares-Inventory-Common-Names.csv"
       
        # Get percent of shared covered by top 5
        # If very weighted this indicates if the shares are part of a deployment process, image, or app
        
        # Get top five share name
        $CommonShareNamesCount = $CommonShareNames.count
        $CommonShareNamesTop5 = $CommonShareNames | Select-Object count,name -First $SampleSum 
        
        # Get count of share name if in the top 5
        $Top5ShareCountTotal = 0
        $CommonShareNamesTop5 |
        foreach{
            [int]$TopCount = $_.Count 
            $Top5ShareCountTotal = $Top5ShareCountTotal + $TopCount
        }
        
        # Get count of all accessible shares
        $AllAccessibleSharesCount = $ExcessiveSharePrivs | Select-Object ComputerName,ShareName -Unique | measure | select count -ExpandProperty count

        # ----------------------------------------------------------------------
        # Calculate percentages
        # ----------------------------------------------------------------------

        # top 5 shares
        $DupDec = $Top5ShareCountTotal / $AllAccessibleSharesCount
        $DupPercent = $DupDec.tostring("P")

        # Expected share count from know defaults
        $MinExpectedShareCount = $Computers445OpenCount * 2

        # Computer ping                      
        $PercentComputerPing = [math]::Round($ComputerPingableCount/$ComputerCount,4)
        $PercentComputerPingP = $PercentComputerPing.tostring("P") -replace(" ","")
        $PercentComputerPingBarVal = ($PercentComputerPing*2).tostring("P") -replace(" %","px")

        # Computer port 445 open              
        $PercentComputerPort = [math]::Round($Computers445OpenCount/$ComputerCount,4) 
        $PercentComputerPortP = $PercentComputerPort.tostring("P") -replace(" ","")
        $PercentComputerPortBarVal = ($PercentComputerPort*2).tostring("P") -replace(" %","")

        # Computer with share        
        $PercentComputerWitShare = [math]::Round($AllComputersWithSharesCount/$ComputerCount,4)
        $PercentComputerWitShareP = $PercentComputerWitShare.tostring("P") -replace(" ","")
        $PercentComputerWitShareBarVal = ($PercentComputerWitShare*2).tostring("P") -replace(" %","px")

        # Computer with non default shares   
        $PercentComputerNonDefault = [math]::Round($ComputerwithNonDefaultCount/$ComputerCount,4)
        $PercentComputerNonDefaultP = $PercentComputerNonDefault.tostring("P") -replace(" ","")
        $PercentComputerNonDefaultBarVal = ($PercentComputerNonDefault*2).tostring("P") -replace(" %","px")

        # Computer with excessive priv shares 
        $PercentComputerExPriv = [math]::Round($ComputerWithExcessive/$ComputerCount,4)
        $PercentComputerExPrivP = $PercentComputerExPriv.tostring("P") -replace(" ","")
        $PercentComputerExPrivBarVal = ($PercentComputerExPriv*2).tostring("P") -replace(" %","px")

        # Computer read  share access       
        $PercentComputerRead = [math]::Round($ComputerWithReadCount/$ComputerCount,4)
        $PercentComputerReadP = $PercentComputerRead.tostring("P") -replace(" ","")
        $PercentComputerReadBarVal = ($PercentComputerRead*2).tostring("P") -replace(" %","px")

        # Computer write share access         
        $PercentComputerWrite = [math]::Round($ComputerWithWriteCount/$ComputerCount,4)
        $PercentComputerWriteP = $PercentComputerWrite.tostring("P") -replace(" ","")
        $PercentComputerWriteBarVal = ($PercentComputerWrite*2).tostring("P") -replace(" %","px")

        # Computer highrisk shares            
        $PercentComputerHighRisk = [math]::Round($ComputerwithHighRisk/$ComputerCount,4)
        $PercentComputerHighRiskP = $PercentComputerHighRisk.tostring("P") -replace(" ","")
        $PercentComputerHighRiskBarVal = ($PercentComputerHighRisk*2).tostring("P") -replace(" %","px")

        # Shares with non default names      
        $PercentSharesNonDefault = [math]::Round($SharesNonDefaultCount/$AllSMBSharesCount,4)
        $PercentSharesNonDefaultP = $PercentSharesNonDefault.tostring("P") -replace(" ","")
        $PercentSharesNonDefaultBarVal = ($PercentSharesNonDefault*2).tostring("P") -replace(" %","px")

        # Shares with excessive priv shares   
        $PercentSharesExPriv = [math]::Round($ExcessiveSharesCount/$AllSMBSharesCount,4)
        $PercentSharesExPrivP = $PercentSharesExPriv.tostring("P") -replace(" ","")
        $PercentSharesExPrivBarVal = ($PercentSharesExPriv*2).tostring("P") -replace(" %","px")

        # Shares with excessive read        
        $PercentSharesRead = [math]::Round($SharesWithReadCount/$AllSMBSharesCount,4)
        $PercentSharesReadP = $PercentSharesRead.tostring("P") -replace(" ","")
        $PercentSharesReadBarVal = ($PercentSharesRead*2).tostring("P") -replace(" %","px")

        # Shares with excessive write         
        $PercentSharesWrite = [math]::Round($SharesWithWriteCount/$AllSMBSharesCount,4) 
        $PercentSharesWriteP = $PercentSharesWrite.tostring("P") -replace(" ","")
        $PercentSharesWriteBarVal = ($PercentSharesWrite*2).tostring("P") -replace(" %","px")

        # Shares with excessive highrisk      
        $PercentSharesHighRisk = [math]::Round($SharesHighRiskCount/$AllSMBSharesCount,4)
        $PercentSharesHighRiskP = $PercentSharesHighRisk.tostring("P") -replace(" ","")
        $PercentSharesHighRiskBarVal = ($PercentSharesHighRisk*2).tostring("P") -replace(" %","px")

        # ACL with non default names          
        $PercentAclNonDefault = [math]::Round($AclNonDefaultCount/$ShareACLsCount,4)
        $PercentAclNonDefaultP = $PercentAclNonDefault.tostring("P") -replace(" ","")
        $PercentAclNonDefaultBarVal = ($PercentAclNonDefault*2).tostring("P") -replace(" %","px")

        # ACL with excessive priv shares      
        $PercentAclExPriv = [math]::Round($ExcessiveSharePrivsCount/$ShareACLsCount,4)
        $PercentAclExPrivP = $PercentAclExPriv.tostring("P") -replace(" ","")
        $PercentAclExPrivBarVal = ($PercentAclExPriv*2).tostring("P") -replace(" %","px")

        # ACL with excessive read           
        $PercentAclRead = [math]::Round($AclWithReadCount/$ShareACLsCount,4)
        $PercentAclReadP = $PercentAclRead.tostring("P") -replace(" ","")
        $PercentAclReadBarVal = ($PercentAclRead *2).tostring("P") -replace(" %","px")

        # ACL with excessive write             
        $PercentAclWrite = [math]::Round($AclWithWriteCount/$ShareACLsCount,4)
        $PercentAclWriteP = $PercentAclWrite.tostring("P") -replace(" ","")
        $PercentAclWriteBarVal = ($PercentAclWrite *2).tostring("P") -replace(" %","px")

        # ACL with excessive highrisk
        $PercentAclHighRisk = [math]::Round($AclHighRiskCount/$ShareACLsCount,4)
        $PercentAclHighRiskP = $PercentAclHighRisk.tostring("P") -replace(" ","")
        $PercentAclHighRiskBarVal = ($PercentAclHighRisk *2).tostring("P") -replace(" %","px")
        
        # ACE User: Everyone
        $AceEveryone = Get-UserAceCounts -DataTable $ExcessiveSharePrivs -UserName "everyone"
        $AceEveryoneAclCount = $AceEveryone.UserAclsCount 
        $AceEveryoneShareCount = $AceEveryone.UserShareCount 
        $AceEveryoneComputerCount = $AceEveryone.UserComputerCount 
        $AceEveryoneAclReadCount = $AceEveryone.UserReadAclCount
        $AceEveryoneAclWriteCount = $AceEveryone.UserWriteAclCount
        $AceEveryoneAclHRCount = $AceEveryone.UserHighRiskAclCount

	    $AceEveryoneAclP = Get-PercentDisplay -TargetCount $AceEveryoneComputerCount -FullCount $ComputerCount 
        $AceEveryoneAclPS = $AceEveryoneAclP.PercentString
        $AceEveryoneAclPB = $AceEveryoneAclP.PercentBarVal

        $AceEveryoneShareCountP = Get-PercentDisplay -TargetCount $AceEveryoneShareCount -FullCount $AllSMBSharesCount 
        $AceEveryoneShareCountPS = $AceEveryoneShareCountP.PercentString
        $AceEveryoneShareCountPB = $AceEveryoneShareCountP.PercentBarVal 
    
        $AceEveryoneComputerCountP = Get-PercentDisplay -TargetCount $AceEveryoneAclCount -FullCount $ShareACLsCount
        $AceEveryoneComputerCountPS = $AceEveryoneComputerCountP.PercentString
        $AceEveryoneComputerCountPB = $AceEveryoneComputerCountP.PercentBarVal 

        # ACE User: Users
        $AceUsers = Get-UserAceCounts -DataTable $ExcessiveSharePrivs -UserName "BUILTIN\Users"
        $AceUsersAclCount = $AceUsers.UserAclsCount 
        $AceUsersShareCount = $AceUsers.UserShareCount 
        $AceUsersComputerCount = $AceUsers.UserComputerCount         
        $AceUsersAclReadCount = $AceUsers.UserReadAclCount
        $AceUsersAclWriteCount = $AceUsers.UserWriteACLCount
        $AceUsersAclHRCount = $AceUsers.UserHighRiskACLCount

        $AceUsersAclP = Get-PercentDisplay -TargetCount $AceUsersComputerCount -FullCount $ComputerCount 
        $AceUsersAclPS = $AceUsersAclP.PercentString
        $AceUsersAclPB = $AceUsersAclP.PercentBarVal

        $AceUsersShareCountP = Get-PercentDisplay -TargetCount $AceUsersShareCount -FullCount $AllSMBSharesCount 
        $AceUsersShareCountPS = $AceUsersShareCountP.PercentString
        $AceUsersShareCountPB = $AceUsersShareCountP.PercentBarVal 
    
        $AceUsersComputerCountP = Get-PercentDisplay -TargetCount $AceUsersAclCount -FullCount $ShareACLsCount
        $AceUsersComputerCountPS = $AceUsersComputerCountP.PercentString
        $AceUsersComputerCountPB = $AceUsersComputerCountP.PercentBarVal 

        # ACE User: Authenticated Users
        $AceAuthenticatedUsers = Get-UserAceCounts -DataTable $ExcessiveSharePrivs -UserName "NT AUTHORITY\Authenticated Users"        
        $AceAuthenticatedUsersComputerCount = $AceAuthenticatedUsers.UserComputerCount 
        $AceAuthenticatedUsersShareCount    = $AceAuthenticatedUsers.UserShareCount 
        $AceAuthenticatedUsersAclCount      = $AceAuthenticatedUsers.UserAclsCount 
        $AceAuthenticatedUsersAclReadCount  = $AceAuthenticatedUsers.UserReadAclCount
        $AceAuthenticatedUsersAclWriteCount = $AceAuthenticatedUsers.UserWriteACLCount
        $AceAuthenticatedUsersAclHRCount    = $AceAuthenticatedUsers.UserHighRiskACLCount

        $AceAuthenticatedUsersAclP = Get-PercentDisplay -TargetCount $AceAuthenticatedUsersComputerCount -FullCount $ComputerCount 
        $AceAuthenticatedUsersAclPS = $AceAuthenticatedUsersAclP.PercentString
        $AceAuthenticatedUsersAclPB = $AceAuthenticatedUsersAclP.PercentBarVal

        $AceAuthenticatedUsersShareCountP = Get-PercentDisplay -TargetCount $AceAuthenticatedUsersShareCount -FullCount $AllSMBSharesCount 
        $AceAuthenticatedUsersShareCountPS = $AceAuthenticatedUsersShareCountP.PercentString
        $AceAuthenticatedUsersShareCountPB = $AceAuthenticatedUsersShareCountP.PercentBarVal 
            
        $AceAuthenticatedUsersComputerCountP = Get-PercentDisplay -TargetCount $AceAuthenticatedUsersAclCount -FullCount $ShareACLsCount
        $AceAuthenticatedUsersComputerCountPS = $AceAuthenticatedUsersComputerCountP.PercentString
        $AceAuthenticatedUsersComputerCountPB = $AceAuthenticatedUsersComputerCountP.PercentBarVal         

        # ACE User: Domain Users
        $AceDomainUsers = Get-UserAceCounts -DataTable $ExcessiveSharePrivs -UserName "Domain Users"
        $AceDomainUsersAclCount      = $AceDomainUsers.UserAclsCount 
        $AceDomainUsersShareCount    = $AceDomainUsers.UserShareCount 
        $AceDomainUsersComputerCount = $AceDomainUsers.UserComputerCount 
        $AceDomainUsersAclReadCount  = $AceDomainUsers.UserReadAclCount
        $AceDomainUsersAclWriteCount = $AceDomainUsers.UserWriteACLCount
        $AceDomainUsersAclHRCount    = $AceDomainUsers.UserHighRiskACLCount

	    $AceDomainUsersAclP = Get-PercentDisplay -TargetCount $AceDomainUsersComputerCount -FullCount $ComputerCount 
        $AceDomainUsersAclPS = $AceDomainUsersAclP.PercentString
        $AceDomainUsersAclPB = $AceDomainUsersAclP.PercentBarVal

        $AceDomainUsersShareCountP = Get-PercentDisplay -TargetCount $AceDomainUsersShareCount -FullCount $AllSMBSharesCount 
        $AceDomainUsersShareCountPS = $AceDomainUsersShareCountP.PercentString
        $AceDomainUsersShareCountPB = $AceDomainUsersShareCountP.PercentBarVal 
    
        $AceDomainUsersComputerCountP = Get-PercentDisplay -TargetCount $AceDomainUsersAclCount -FullCount $ShareACLsCount
        $AceDomainUsersComputerCountPS = $AceDomainUsersComputerCountP.PercentString
        $AceDomainUsersComputerCountPB = $AceDomainUsersComputerCountP.PercentBarVal 

        # ACE User: Domain Computers
        $AceDomainComputers = Get-UserAceCounts -DataTable $ExcessiveSharePrivs -UserName "Domain Computers"
        $AceDomainComputersAclCount = $AceDomainComputers.UserAclsCount 
        $AceDomainComputersShareCount = $AceDomainComputers.UserShareCount 
        $AceDomainComputersComputerCount = $AceDomainComputers.UserComputerCount
        $AceDomainComputersAclReadCount = $AceDomainComputers.UserReadAclCount
        $AceDomainComputersAclWriteCount = $AceDomainComputers.UserWriteACLCount
        $AceDomainComputersAclHRCount = $AceDomainComputers.UserHighRiskACLCount
        
	    $AceDomainComputersAclP = Get-PercentDisplay -TargetCount $AceDomainComputersComputerCount -FullCount $ComputerCount 
        $AceDomainComputersAclPS = $AceDomainComputersAclP.PercentString
        $AceDomainComputersAclPB = $AceDomainComputersAclP.PercentBarVal

        $AceDomainComputersShareCountP = Get-PercentDisplay -TargetCount $AceDomainComputersShareCount -FullCount $AllSMBSharesCount 
        $AceDomainComputersShareCountPS = $AceDomainComputersShareCountP.PercentString
        $AceDomainComputersShareCountPB = $AceDomainComputersShareCountP.PercentBarVal 
    
        $AceDomainComputersComputerCountP = Get-PercentDisplay -TargetCount $AceDomainComputersAclCount -FullCount $ShareACLsCount
        $AceDomainComputersComputerCountPS = $AceDomainComputersComputerCountP.PercentString
        $AceDomainComputersComputerCountPB = $AceDomainComputersComputerCountP.PercentBarVal          
        
        Write-Output " [*] - $Top5ShareCountTotal of $AllAccessibleSharesCount ($DupPercent) shares are associated with the top 5 share names."

        # ----------------------------------------------------------------------
        # Display final summary
        # ----------------------------------------------------------------------
        Write-Output " [*] Results written to $OutputDirectory"
        Write-Output " [*] "

        $EndTime = Get-Date
        $StopWatch.Stop()
        $RunTime = $StopWatch | Select-Object Elapsed -ExpandProperty Elapsed

        Write-Output " [*] -----------------------------------------------"
        Write-Output " [*] Get-ShareInventory Summary Report"
        Write-Output " [*] -----------------------------------------------"
        Write-Output " [*] Domain: $TargetDomain"
        Write-Output " [*] Start time: $StartTime"
        Write-Output " [*] End time: $EndTime"
        Write-Output " [*] Run time: $RunTime"
        Write-Output " [*] "
        Write-Output " [*] Computer Summary"
        Write-Output " [*] - $ComputerCount domain computers found."
        Write-Output " [*] - $ComputerPingableCount ($PercentComputerPingP) domain computers responded to ping."
        Write-Output " [*] - $Computers445OpenCount ($PercentComputerPortP) domain computers had TCP port 445 accessible."
        Write-Output " [*] - $ComputerwithNonDefaultCount ($PercentComputerNonDefaultP) domain computers had shares that were non-default."  
        Write-Output " [*] - $ComputerWithExcessive ($PercentComputerExPrivP) domain computers had shares with potentially excessive privileges."      
        Write-Output " [*] - $ComputerWithReadCount ($PercentComputerReadP) domain computers had shares that allowed READ access."  
        Write-Output " [*] - $ComputerWithWriteCount ($PercentComputerWriteP) domain computers had shares that allowed WRITE access."  
        Write-Output " [*] - $ComputerwithHighRisk ($PercentComputerHighRiskP) domain computers had shares that are HIGH RISK."  
        Write-Output " [*] "
        Write-Output " [*] Share Summary"      
        Write-Output " [*] - $AllSMBSharesCount shares were found. We expect a minimum of $MinExpectedShareCount shares, because $Computers445OpenCount systems had open ports and there are typically two default shares."
        Write-Output " [*] - $SharesNonDefaultCount ($PercentSharesNonDefaultP) shares across $ComputerwithNonDefaultCount systems were non-default."
        Write-Output " [*] - $ExcessiveSharesCount ($PercentSharesExPrivP) shares across $ComputerWithExcessive systems are configured with $ExcessiveSharePrivsCount potentially excessive ACLs."
        Write-Output " [*] - $SharesWithReadCount ($PercentSharesReadP) shares across $ComputerWithReadCount systems allowed READ access."
        Write-Output " [*] - $SharesWithWriteCount ($PercentSharesWriteP) shares across $ComputerWithWriteCount systems allowed WRITE access."
        Write-Output " [*] - $SharesHighRiskCount ($PercentSharesHighRiskP) shares across $ComputerwithHighRisk systems are considered HIGH RISK."
        Write-Output " [*] "
        Write-Output " [*] ACL Summary"
        Write-Output " [*] - $ShareACLsCount ACLs were found."
        Write-Output " [*] - $AclNonDefaultCount ($PercentAclNonDefaultP) ACLs were associated with non-default shares." 
        Write-Output " [*] - $ExcessiveSharePrivsCount ($PercentAclExPrivP) ACLs were found to be potentially excessive."               
        Write-Output " [*] - $AclWithReadCount ($PercentAclReadP) ACLs were found that allowed READ access."  
        Write-Output " [*] - $AclWithWriteCount ($PercentAclWriteP) ACLs were found that allowed WRITE access."                               
        Write-Output " [*] - $AclHighRiskCount ($PercentAclHighRiskP) ACLs were found that are associated with HIGH RISK share names."
        Write-Output " [*] "
        Write-Output " [*] - The 5 most common share names are:"
        Write-Output " [*] - $Top5ShareCountTotal of $AllAccessibleSharesCount ($DupPercent) discovered shares are associated with the top 5 share names."
        $CommonShareNamesTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareName = $_.name
            Write-Output " [*]   - $ShareCount $ShareName"   
        }
        Write-Output " [*] -----------------------------------------------"
        
        # ----------------------------------------------------------------------
        # Display final summary - NEW HTML REPORT
        # ----------------------------------------------------------------------
		if($username -like ""){$username = whoami}
		$SourceIps = (Get-NetIPAddress | where AddressState -like "*Pref*" | where AddressFamily -like "ipv4" | where ipaddress -notlike "127.0.0.1" | select IpAddress).ipaddress -join (",")
		$SourceHost = (hostname) 

        # Get share list string list
       $CommonShareFileGroupTopString = $CommonShareFileGroupTop5 |
        foreach {
            $FileGroupName = $_.name              
            $ThisFileBars = Get-GroupFileBar -DataTable $ExcessiveSharePrivs -Name $FileGroupName -AllComputerCount $ComputerCount -AllShareCount $AllSMBSharesCount -AllAclCount $ShareACLsCount
            $ComputerBarF = $ThisFileBars.ComputerBar
            $ShareBarF = $ThisFileBars.ShareBar
            $AclBarF = $ThisFileBars.AclBar
            $ThisFileList = $ThisFileBars.FileList           
            $ThisFileCount = $ThisFileBars.FileCount
            $ThisFileShareCount = $ThisFileBars.Sharecount
            $ThisRow = @" 
	          <tr>
	          <td>
              $ThisFileShareCount
	          </td>	
	          <td>
              $FileGroupName
	          </td>	
	          <td>
              $ThisFileCount
	          </td>		  
	          <td>
              $ThisFileList
	          </td>
	          <td>
	          $ComputerBarF
	          </td>		  
	          <td>
	          $ShareBarF
	          </td>  
	          <td>
	          $AclBarF
	          </td>          	  
	          </tr>
"@              
            $ThisRow
        }

        # Get share name string list
        $CommonShareNamesTopString = $CommonShareNamesTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareName = $_.name
            Write-Output "$ShareCount $ShareName <br>"   
        }  

        # Get share name string list table
        $CommonShareNamesTopStringT = $CommonShareNamesTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareName = $_.name
            $ShareNameBars = Get-GroupNameBar -DataTable $ExcessiveSharePrivs -Name $ShareName -AllComputerCount $ComputerCount -AllShareCount $AllSMBSharesCount -AllAclCount $ShareACLsCount
            $ComputerBar = $ShareNameBars.ComputerBar
            $ShareBar = $ShareNameBars.ShareBar
            $AclBar = $ShareNameBars.AclBar
            $ThisRow = @" 
	          <tr>
	          <td>
              $ShareCount
	          </td>	
	          <td>
              $ShareName
	          </td>		  
	          <td>
	          $ComputerBar     	 
	          </td>		  
	          <td>
	          $ShareBar    	 
	          </td>  
	          <td>
	          $AclBar     	 
	          </td>          	  
	          </tr>
"@              
            $ThisRow  
        } 

        # Get owner string list 
        $CommonShareOwnersTop5String = $CommonShareOwnersTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareOwner = $_.name
            Write-Output "$ShareCount $ShareOwner<br>"   
        } 

        # Get owner string list table
        $CommonShareOwnersTop5StringT = $CommonShareOwnersTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareOwner = $_.name
            $ShareOwnerBars = Get-GroupOwnerBar -DataTable $ExcessiveSharePrivs -Name $ShareOwner -AllComputerCount $ComputerCount -AllShareCount $AllSMBSharesCount -AllAclCount $ShareACLsCount
            $ComputerBarO = $ShareOwnerBars.ComputerBar
            $ShareBarO = $ShareOwnerBars.ShareBar
            $AclBarO = $ShareOwnerBars.AclBar
            $ThisRow = @" 
	          <tr>
	          <td>
              $ShareCount
	          </td>	
	          <td>
              $ShareOwner
	          </td>		  
	          <td>
	          $ComputerBarO
	          </td>		  
	          <td>
	          $ShareBarO
	          </td>  
	          <td>
	          $AclBarO
	          </td>          	  
	          </tr>
"@              
            $ThisRow    
        } 

        
$NewHtmlReport = @" 
<html>
<head>
  <link rel="shortcut icon" src="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyhpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNi1jMTM4IDc5LjE1OTgyNCwgMjAxNi8wOS8xNC0wMTowOTowMSAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTcgKE1hY2ludG9zaCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6QTQxQkNBNzA2OEI1MTFFNzlENkRCMzJFODY4RjgwNDMiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6QTQxQkNBNzE2OEI1MTFFNzlENkRCMzJFODY4RjgwNDMiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpBNDFCQ0E2RTY4QjUxMUU3OUQ2REIzMkU4NjhGODA0MyIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDpBNDFCQ0E2RjY4QjUxMUU3OUQ2REIzMkU4NjhGODA0MyIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/Ptdv5vcAAAB9SURBVHjaYmTAAS4IajsCqeVQbqTB+6v7saljxKHZCUhtAWJOqNB3IPYBGrKPoAFYNDPgM4SRSM04DWEkQTNWQxhJ1IxhCCM0tLeSoBnZEG+QAS+ADHEG8sBLJgYKAciASKhzGMjwQiTlgUiVaKRKQqJKUqZKZiI1OwMEGAA7FE70gYsL4wAAAABJRU5ErkJggg==" >
  <title>Report</title>
  <style>    	

.1collapsible:after {
	  content: '\0208A';
	  font-size: 30;
	  color: gray;
	  padding: 5px;
	  font-weight: bold;
	}

	.1active:after {
	  content: "\0078"; 
	  font-size: 30;
	  color: gray;
	  padding: 5px;
	  --font-weight: bold;	  
	}
  
	.collapsible {
		font-family:"Open Sans", sans-serif;
		font-size:20;
		font-weight:600;
		color: #333;	
		padding-left:0px;
		background-color: inherit;
		cursor: pointer;
		border: none;
		outline: none;		
	}

	.active, .collapsible:hover {
	  --background-color: #555;
	  color:#CE112D;
	  --font-weight:bold;
	}

	.content {
	  max-height: 0;
	  overflow: hidden;
	  transition: max-height 0.2s ease-out;
	}

	.tabs{
		margin-top: 10px;
		display:-webkit-box;
		display:-ms-flexbox;
		display:flex;
		-ms-flex-wrap:wrap;
		flex-wrap:wrap;
		width:100%
	}
	
	.tabInput{
		position:fixed;
		top:0;
		left:0;
		opacity:0
	}
	
	.tabLabel{
		width:auto;
		color:#C4C4C8;
		--font-weight:bold;
		--cursor:pointer;
		padding-left: 15px;
		--border-bottom:2px solid transparent;
		-webkit-box-ordinal-group:2;
		-ms-flex-order:1;
		order:1;
		--border-radius:0.80rem 0.80rem 0.80rem 0.80rem
	}
	
	.tabLabel:focus{
		outline:0	
		background-color:red;
	}
	
	.tabInput:target+
	.tabLabel,
	.tabInput:checked+
	.tabLabel{
		--background:white;
		--border-bottom-color:#9B3722;
		--border-bottom:2px solid;
		--color:#9B3722; red
		font-weight: bold;
	}

	.stuff {
		color:#C4C4C8;
		font-weight: bold;
		font-weight: normal;	
		width:auto;		
		text-decoration: none;
		padding-top:5px;
		padding-bottom:5px;
		padding-left:15px;
		order:1;
	}

	.stuff:hover{
		font-weight: normal;
		background-color:#555555;
		text-decoration: none;
		padding-top:5px;
		padding-bottom:5px;
	}	
	

	.stuff:active {
		font-weight: normal;		 
		background-color:#5D5C5C;		
		width:auto;		
		padding-left: 15px;	
	}	
	
	.stuff:visited {
		font-weight: normal;
		color:#C4C4C8;	
		width:auto;		
		padding-left: 15px;			
	}		

	.tabLabel:hover{
		background-color:#555555;		
		color:#ccc;
		--border-color:#eceeef #eceeef #ddd			
	}
		
	.tabPanel{
		display:none;width:100%;
		-webkit-box-ordinal-group:100;
		-ms-flex-order:99;order:99
	}
	
	.tabInput:target+
	.tabLabel+.tabPanel,
	.tabInput:checked+
	.tabLabel+
	.tabPanel{
		display:block
	}
	
	.tabPanel.nojs{
		opacity:0
	}
  
	{box-sizing:border-box}
	body,html{
		font-family:"Open Sans", 
		sans-serif;font-weight:400;
		min-height:100%;
		color:#3d3935;
		margin:0px;
		line-height:1.5;
		overflow-x:hidden
		font-family:"Proxima Nova","Open Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
		font-size:14px;
		font-weight:normal;
		line-height:1.3;
		background-color:#f0f3f5;
		--color:#333;
		--background-color:#DEDFE1
	}
		
	table{
		width:100%;
		max-width:100%;
		--margin-bottom:1rem;
		border-collapse:collapse;		
	}
	
	.tabledrop {
		border-right:1px solid #BEDFE1;
		border-left:1px solid #BEDFE1;
		border-bottom:1px solid #BEDFE1;
		--border:1px solid #757575;
		--border-top:1.5px solid #757575;
		--box-shadow: 0 0 0 0;
		box-shadow: 0 2px 4px 0 #DEDFE1;
		margin: 10px;
		width: 90%;
		--margin-left:10px;
	}	
	
	table thead th{
		vertical-align:bottom;
		background-color: #3D3935;
		color:white;
		border:1px solid #3D3935;
	}
	
	table tbody tr{
		background-color:white;	
		--font-weight: bold;		
	}	
	
	table tbody tr:nth-of-type(odd){
		--background-color:#F0E8E8;
		background-color:#f9f9f9;		
	}
	
	table tbody tr:hover{
		background-color:#ECF1F1;	
		--font-weight: bold;		
	}
	
	table td,table th{
		padding:.75rem;
		line-height:1.5;
		text-align:left;
		font-size:1rem;
		vertical-align:top;
		border-top:1px solid #eceeef
	}
	
	h2{
		font-size:2rem
	}
		
	h3{
		font-size:1.75rem
	}
	
	h4{
		font-size:1.5rem
	}
	
	h1,h2,h3,h4,h5,h6{
		margin-bottom:.5rem;
		margin-top:0px;
		font-family:inherit;
		font-weight:500;
		line-height:1.1;
		color:inherit
	}
	
	label{
		display:inline-block;
		padding-top:.5rem;
		padding-bottom:.25rem;
		--margin-bottom:.5rem
	}
	
	code{
		padding:.2rem .4rem;
		font-size:1rem;
		color:#bd4147;
		background-color:#f7f7f9;
		-border-radius:.25rem
	}
	
	p{
		margin-top:0;
		margin-bottom:1rem
	}
	
	a,a:visited{
		text-decoration:none;
		font-size: 14;
		color: gray;
		font-weight: bold;
	}
	
	a:hover{
		--color:#9B3722;
		text-decoration:underline
	}
	
	.preload *{
		-webkit-transition:none !important;
		-moz-transition:none !important;
		-ms-transition:none !important;
		-o-transition:none !important
	}
	
	.header{
		text-align:center
	}

    .noscroll{
        overflow:hidden
    }
	
	.link:hover{
		text-decoration:underline
	}
	
	li{
		list-style-type:none
	}
	
	.mobile{
		display:none;
		height:0;
		width:0
	}
	
	@media (max-width: 700px){
		.mobile{display:block !important}
	}
	
	code{
		color:black;
		font-family:monospace
	}
	
	ul.noindent{
		padding-left:20px
	}

    .pageDescription {
        margin: 10px;
		width:90%;
    }
	
	.pagetitle {
		font-size: 20;
		font-weight:bold;
		--color:#9B3722;
		--color:#CE112D;
		color:#222222;
	}
	
	.pagetitlesub {
		font-size: 20;
		font-weight:bold;
		--color:#9B3722;
		color:#CE112D;
		--color:#222222;
	}	
	
	.topone{background:#999999}
  
	.divbarDomain{
		background:#d9d7d7;
		width:200px;
		--border: 1px solid #999999;
		height: 15px;
		text-align:center;
	}
  
	.divbarDomainInside{
		--background:#9B3722;
		background:#CE0E2D;		
		text-align:center;
		height: 15px;
		vertical-align:middle;
	}
	
	.piechartComputers {    		
        display: block;
        width: 130px;
        height: 130px;
        background: radial-gradient(white 60%, transparent 41%), 
		conic-gradient(#CE112D 0% $PercentComputerExPrivP, 
					   #d9d7d7 $PercentComputerExPrivP 100%);
		border-radius: 50%;
		text-align: center;
		margin-top: 5px;
		margin-bottom: 10px;
    }

	.piechartShares {    
        display: block;
        width: 130px;
        height: 130px;
        background: radial-gradient(white 60%, transparent 41%), 
		conic-gradient(#CE112D 0% $PercentSharesExPrivP, 
					   #d9d7d7 $PercentSharesExPrivP 100%);
		border-radius: 50%;
		text-align: center;
		margin-top: 5px;
		margin-bottom: 10px;
    }
	
	.piechartAcls {         
		display: block;
        width: 130px;
        height: 130px;
        background: radial-gradient(white 60%, transparent 41%), 
		conic-gradient(#CE112D 0% $PercentAclExPrivP, 
					   #d9d7d7 $PercentAclExPrivP 100%);
		border-radius: 50%;
		text-align: center;
		margin-top: 5px;
		margin-bottom: 10px;
    }

	.percentagetextBuff {
		--height: 25%;
	}	
	
	.percentagetext {
		text-align: center;
		font-size: 2.25em;
		font-weight: 700;
		font-family:"Open Sans", sans-serif;
		--color:#9B3722;
		color:#CE112D;
	}
	
	.percentagetext2 {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#666;			
		text-align: center;
	}	

	.dashboardsub {
		text-align: center;
		font-size: 12;
		font-family:"Open Sans", sans-serif;
		color:#666;
		font-weight: bold;
	}
	
	.dashboardsub2 {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#666;		
		text-align: right;
	}	

	.landingheader	{
		font-size: 16;
		font-family:"Open Sans", sans-serif;
		color: #CE112D;
		font-weight: bold;	
		padding-left:0px;
	}

	.landingheader2	{
		font-size: 16;	
		--font-weight: bold;		
		color:White;
		--color:9B3722;
		--background-color: #ccc;		
		border-bottom: 2px solid #999;		
		padding-left:15px;
	}	
	
	.landingheader2a	{
        background-color: 9B3722;
		--background-color: #999;		
		padding-left:120px;;
		padding-right: 5px;
	}	

	.landingheader2b	{
        background-color: 9B3722;
		--background-color: #999;		
		padding-left: 5px;
		padding-right: 5px;
		margin-top: 10px;
		margin-left: 10px;
		font-size: 16;
		color:White;	
	}		
	
	.landingtext {
		font-size: 14;
		font-family:"Open Sans", sans-serif;
		color:#666;
		background-color:white;
		border-radius: 25px;
		padding: 20px;
		margin-top: 10px;
		margin-right: 10px;
		margin-bottom: 15px;
		width: 90%		
	}
	
	.landingtext2 {
		font-size: 14;
		font-family:"Open Sans", sans-serif;
		color:#666;
		padding-top: 5px;
		padding-bottom: 20px;
		padding-left:15px;
	}	

	.tablecolinfo {
		font-size: 14;
		font-family:"Open Sans", sans-serif;
		color:#666;		
	}

	.card {
		width: 230px;
		box-shadow: 0 2px 4px 0 #DEDFE1;	
		transition:0.3s;
		background-color: #3D3935;
		font-family:"Open Sans", sans-serif;
		font-size: 12;
		font-weight: 2;
		font-color: black;
		float: left;
		--overflow:auto;
		display:block;
		margin:10px;
		margin-bottom:20px;
	}

	.card:hover{	
		box-shadow: 0 8px 16px 0;
		--box-shadow: 0 8px 16px 0 #DEDFE1;
		
	}	

	.cardtitle{	
		padding:5px;	
		padding-left: 10px;
		font-size:15;
		color: white;
		font-weight:bold;
		font-family:"Open Sans", sans-serif;
		border-bottom:1.5px solid transparent;
		border-bottom-color:#757575;
	}

	.cardsubtitle {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#222222;	
		text-align: right;
		font-weight: bold;
	}	

	.cardsubtitle2 {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#eee;	
		text-align: right;
		font-weight: bold;
	}		

	.cardbartext {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#666;			
		text-align: right;
		margin-left: 10px;		
		font-weight:bold;
	}

	.cardbartext2 {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color:#666;			
		text-align: right;
		margin-left: 10px;
	}
	
	.cardtitlescan{	
		padding:5px;	
		padding-left: 10px;
		font-size:15;
		color: white;
		font-weight:bold;
		font-family:"Open Sans", sans-serif;
		border-bottom:1.5px solid transparent;
		border-bottom-color:#222222;
		background-color: #222222;
	}

	.cardtitlescansub {
		font-size: 10;
		font-family:"Open Sans", sans-serif;
		color: #eee;			
		text-align: center;
	}

	.cardcontainer {
		background-color:white;
		padding: 8px;
		: center;
		--padding-left: 10px;	
	}		

	.cardbarouter{
		background:#d9d7d7;
		width:102px;
		--border: 1px solid #999999;
		height: 15px;
		margin-left: 10px;
		text-align:center;
	}
	  
	.cardbarinside{
		--background:#9B3722;
		background:#CE112D;
		text-align:center;
		height: 15px;
		vertical-align:middle;
        width: 0px;
	}	

	.AclEntryWrapper {
		--width: 300px;
		overflow: hidden; 
	}

	.AclEntryLeft {
		width: 75px;
		float:left;
		font-size: 12;
		font-family:"Open Sans", sans-serif;
		color:#666;	
        --font-weight:bold;		
	}
	.AclEntryRight{
		float: left; 
		font-size: 12;
		font-family:"Open Sans", sans-serif;
		color:#666;			
	}

	.sidenavcred{
		font-size: 12;
		font-family:"Open Sans", sans-serif;
		color: white;			
		text-align: left;
		padding-left:15px;
	}
	
.sidenav {
    box-shadow: 0 2px 4px 0;
	width: 180px;
	height: 100%;
	background-color:#222222;
	position: fixed; /* Stay in place */
	top: 0; 
	left: 0;
	float:left;
	line-height:1.15;
	-webkit-text-size-adjust:100%;
	-ms-text-size-adjust:100%;
}

.sidenav a {
		width:auto;
		cursor:initial;
		border-bottom:2px solid transparent;
		-webkit-box-ordinal-group:2;
		-ms-flex-order:1;
		order:1;
}

#main {
	margin-left: 190px;
	margin-right: 10px;
	--padding-left: 20px;
}

  </style>
</head>
<body onload="radiobtn = document.getElementById('home');radiobtn.checked = true;">

<!--  
|||||||||| SIDE MENU
-->
<div class="sidenav">	
	
	<div style="border-bottom:1px solid red;width: 72%;display: block;margin-left:20px">
		
		<img style="float: left;margin-top:5px;" src="data:image/png;base64, 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CiAgICB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIgogICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICAgeG1sbnM6R0lNUD0iaHR0cDovL3d3dy5naW1wLm9yZy94bXAvIgogICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iCiAgICB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iCiAgIHhtcE1NOkRvY3VtZW50SUQ9ImdpbXA6ZG9jaWQ6Z2ltcDo5ZDViZjdlMC1mYjI0LTQ2MmItYjY5Yi1lMzhjNWYyZDJlOWYiCiAgIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6OTlmN2M0NTUtNDY5Yy00NzQ0LTg1N2MtZTYzYzZlMmQxYjdjIgogICB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6ZWZjYzQ4MDktNTdkNy00MGI1LWE5MjQtMjU2YmNmMDczODVhIgogICBkYzpGb3JtYXQ9ImltYWdlL3BuZyIKICAgR0lNUDpBUEk9IjIuMCIKICAgR0lNUDpQbGF0Zm9ybT0iV2luZG93cyIKICAgR0lNUDpUaW1lU3RhbXA9IjE2NDI3MjM5ODY0OTQ3ODgiCiAgIEdJTVA6VmVyc2lvbj0iMi4xMC4yOCIKICAgdGlmZjpPcmllbnRhdGlvbj0iMSIKICAgeG1wOkNyZWF0b3JUb29sPSJHSU1QIDIuMTAiPgogICA8eG1wTU06SGlzdG9yeT4KICAgIDxyZGY6U2VxPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDozYzVkNzU5OC1mYjcwLTQzMDAtOGE3NC04MzJjYjZmZTZkMTkiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjItMDEtMjBUMTg6MTM6MDYiLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgIAo8P3hwYWNrZXQgZW5kPSJ3Ij8+JryC6AAAAAZiS0dEAOgA9ABKxSNE4wAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+YBFQANBgqjB1oAAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAAA+klEQVQ4y63VPW7CMABA4efQe+Ab2McIokWFARbEgAo9RQ9SQGVhZWJCQkIiF3Bu4JULpB2QwhIQpDE4hLdFsj7JvwGPYqnfYqnbPmOFB/YNjLPPFdBV1vw9BOawUxugpaz5LQU6sFNb4FVZk3iBsdQTYHRnNXZAI4+KAmwKfOBXBISX6Bk0UgsBM2BIua5QkWEvAuZAn8c6oyKb5hLoUK0ICGux1D3gi+rVgX3Ak3v6lAOAFHrAoiqmrEkCAG3NIYUB8FMFcx1sn1viPNj/NkVZMwamHtgujxWCF+jkBrYtusdOMEM/HegaaBZhN0EHugLeXW+hd2V+AUc5imitOtAG/AAAAABJRU5ErkJggg=="/> 
		<div  style="font-size: 15;font-weight:bolder;color:white;margin-bottom:10px;margin-left:30px; margin-top:30px;">SMB SHARE<br>HUNTER</div>
	</div>

    <div style="width: 72%;display: block;margin-left:20px">			
		<div  style="font-size: 15;font-weight:bolder;color:white;margin-bottom:10px; margin-top:10px;text-align:center;">$TargetDomain</div>			
	</div>	

	<div id="tabs" class="tabs" data-tabs-ignore-url="false">
		<label href="#" class="stuff" style="width:100%;margin-top:15px" onClick="radiobtn = document.getElementById('home');radiobtn.checked = true;">Home</label>		
		<label class="tabLabel" style="width:100%;color:white;background-color:#333;border-top:1px solid #757575;padding-top:5px;padding-bottom:5px;margin-top:1px;margin-bottom:2px;font-weight:bolder"><Strong>Reports</Strong></label>	
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('dashboard');radiobtn.checked = true;">Dashboard Charts</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('computersummary');radiobtn.checked = true;">Computer Summary</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('sharesum');radiobtn.checked = true;">Share Summary</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('ACLsum');radiobtn.checked = true;">ACL Summary</label>		
		<label class="tabLabel" style="width:100%;color:white;background-color:#333;padding-top:5px;padding-bottom:5px;margin-top:5px;margin-bottom:2px;"><Strong>Data Insights</Strong></label>	  	  	
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('accounts');radiobtn.checked = true;">Group Stats</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('ShareName');radiobtn.checked = true;">Top Share Names</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('ShareOwner');radiobtn.checked = true;">Top Share Owners</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('ShareFolders');radiobtn.checked = true;">Top Share Folders</label>		
		<label class="tabLabel" style="width:100%;color:white;background-color:#333;padding-top:5px;padding-bottom:5px;margin-top:5px;margin-bottom:2px;"><strong>Recommendations</strong></label>
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('Attacks');radiobtn.checked = true;">Exploit Share Access</label>		
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('Detections');radiobtn.checked = true;">Detect Share Scans</label>
		<label href="#" class="stuff" style="width:100%;" onClick="radiobtn = document.getElementById('Remediation');radiobtn.checked = true;">Prioritize Remediation</label>		
	</div>
	<img style="float: right;" src="data:image/png;base64, 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" />
	<div class="sidenavcred" style="border-top:1px solid #757575;position: absolute;bottom:0px;width:91%;color:#757575;background-color:#222222">
		<br>
		<strong style="color:#DEDFE1;">Invoke-HuntSMBShares</strong><br>
		<strong>Author:</strong> Scott Sutherland<br>
		<strong>License:</strong> 3-clause BSD<br>
		<br>
	</div>
</div>
<div id="main">

<!--  
|||||||||| PAGE: SCAN SUMMARY
-->
		<input class="tabInput"  name="tabs" type="radio" id="dashboard"/>
		<label class="tabLabel" onClick="updateTab('dashboard',false)" for="dashboard"></label>
		<div id="tabPanel" class="tabPanel">
		<p class="pageDescription" >
			<span class="PageTitle">$TargetDomain  </span> <span class="PageTitleSub">Dashboard Charts</span><br>				
			Below is a summary of the shares configured with excessive privileges on computers associated with the $TargetDomain Active directory domain.
			<a href="$ExcessiveSharePrivsFile">Download Details</a>			
		</p>

<!--  
|||||||||| CARD: COMPUTER SUMMARY
-->

<a href="#" id="DashLink" onClick="radiobtn = document.getElementById('computersummary');radiobtn.checked = true;">
 <div class="card">	
	<div class="cardtitle">
		Computers<br>
		<span class="cardsubtitle2">hosting shares with excessive privileges</span>
	</div>
	<div class="cardcontainer" align="center">	
			<span class="piechartComputers">
				<span class="percentagetext">
					<div class="percentagetextBuff"></div>
                    <img style ="padding-top:20px; padding-bottom:5px;border-bottom:1px solid #ccc; padding-left:10px; padding-right:10px;"  src="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAYAAADE6YVjAAABhWlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw1AUhU9TpSIVByuKdMhQnSyIijhKFYtgobQVWnUweekfNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfE0clJ0UVKvC8ptIjxwuN9nHfP4b37AKFRYarZNQGommWk4jExm1sVA6/wYRBDCMMvMVNPpBcz8Kyve+qmuovyLO++P6tPyZsM8InEc0w3LOIN4plNS+e8TxxiJUkhPiceN+iCxI9cl11+41x0WOCZISOTmicOEYvFDpY7mJUMlXiaOKKoGuULWZcVzluc1UqNte7JXxjMaytprtMKI44lJJCECBk1lFGBhSjtGikmUnQe8/CPOP4kuWRylcHIsYAqVEiOH/wPfs/WLExNuknBGND9Ytsfo0BgF2jWbfv72LabJ4D/GbjS2v5qA5j9JL3e1iJHQP82cHHd1uQ94HIHGH7SJUNyJD8toVAA3s/om3LAwC3Qu+bOrXWO0wcgQ7NavgEODoGxImWve7y7p3Nu//a05vcDTXRymDSRgz8AAAAGYktHRADoAPQASsUjROMAAAAJcEhZcwAALiMAAC4jAXilP3YAAAAHdElNRQfmARYWEjACXexxAAAAGXRFWHRDb21tZW50AENyZWF0ZWQgd2l0aCBHSU1QV4EOFwAAAb5JREFUSMftlM9LKlEUx8+dce44DkxSu0J50Zj4oAQLpHAlDb4/QKF14dqVtGvnuoW0eTsTIfwfFHNX74EoFLQZQnAz6UDjIp3u7bboB9VYgUKbPHDgwrn3fO75nnMvwNSmNrWvDD0v6vX6bLFY/GtZ1q9JEjLGwOfznfj9/r1MJkMAAFyvgmqz2fyjadqRoijX40La7fbvwWCwI4riPgC8hQAAYozRTqdzmMvlzseFJBKJlKqqWwi9iATcqHInlMuRgPuOxk8hPxTiej++hBAci8XcE4yw8CGEUtqXZZlrtVrHjLHhuBDTNGcCgUCf5/l7B6RSqdypqmoYhrE80Wf4+NJPer2eBwBuAQCgVCqhfD6/kUwmrzDGDCHkcIwxFQSBjHA6ar/X671Pp9OnhUJhEQAAZbPZzUajcVyr1XyEEMfNIpEIiUajB7Zt997HRFFcLZfL291u1zFAiqKApmn/w+Fwipdl+axarS5QSkeW73a7OZ7n1yRJWuc47oYxNicIgt80zV3DMFZ0XXfZtu04NxwOQdf1eY/HE3SFQqF/kiQtfKW1ZVkMIbT0pDuilF5ijFE8Hv+sPywYDF48AIWNts4Xc2voAAAAAElFTkSuQmCC" />
					$PercentComputerExPrivP<br>
					<span class="percentagetext2"><span style="color:#9B3722;font-size:12;">$ComputerWithExcessive</span> of $ComputerCount</span>
				</span>
			</span>			
	<table>
		 <tr>
			<td class="cardsubtitle" style="vertical-align: top; width:100px;">Read Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentComputerReadP;"></div>
				</div>	
				<span class="cardbartext">$PercentComputerReadP ($ComputerWithReadCount of $ComputerCount)</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Write Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentComputerWriteP;"></div>
				</div>
				<span class="cardbartext">$PercentComputerWriteP ($ComputerWithWriteCount of $ComputerCount)</span>
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">High&nbsp;Risk</td>
			<td align="right">
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentComputerHighRiskP;"></div>
				</div>
				<span class="cardbartext">$PercentComputerHighRiskP ($ComputerwithHighRisk of $ComputerCount)</span>				
			</td>
		 </tr>		 
		</table> 		  
	</div>
 </div>
</a>

<!--  
|||||||||| CARD: SHARE SUMMARY
-->

<a href="#" id="ShareLink" onClick="radiobtn = document.getElementById('sharesum');radiobtn.checked = true;">
 <div class="card">	
	<div class="cardtitle">
		Shares<br>
		<span class="cardsubtitle2">configured with excessive privileges</span>
	</div>
	<div class="cardcontainer" align="center">	
			<span class="piechartShares">
				<span class="percentagetext">
					<div class="percentagetextBuff"></div>
                    <img style ="padding-top:20px; padding-bottom:5px;border-bottom:1px solid #ccc;padding-left:10px; padding-right:10px;"  src="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAABkAAAAZCAQAAABu4E3oAAABJWlDQ1BJQ0MgcHJvZmlsZQAAKJGdkL1KA0EUhc9G0SBaKVGCxRa2ARu3svEHlxSBuFnB1Wozs8HgzrjsTAi+gW+iD5NCEHwEH0DB2jOrhYXTeIfL/bjce87MAK2wFMos7wNK2zpOjrLL7CpcfUOADs82dnJhqsHoLIU3Pl85zXjpOS3/3J+xIgsjWBdMLaraAsEhOZrbyjETW7dpckJ+IIdSaUl+Iu9JJR273USVM/Gj6W6zXuiLkeszdxGjjwGGCDHGDFOUsOixanZOEeGANUaNHPcwEKwlCvbmnLG4IRkqxTgmpSTexuPXbfyGdBlTY0ot53AHRU3nB/e/32sf581m0FlUeZ03rSVmazIB3h+BjQzYfAbWrj1e7d9v88xEzcw/3/gF/GJQb3mdv/oAAAACYktHRADnlONU6QAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+YBFhYZNZHDwTUAAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAABFElEQVQ4y+3RO0pDURSF4S8xsRBFDVyCoEJALKwcgmBtYWPho1ERbBScg1baiCOwsolWARVxAjqAWImQYCGCGAMWJrFIws2Lq7W4m3PgnLX+tffmv/5IxYw4MARK9hV/lsQNm3UlJ6dk5TeUhJp3F8q4c+bGZ9efqoKPVkk9HhTc2uthO6BqtdVq0qXByCTT8lKdlLCSUg1mWIGYQD/48proGMaO7S6bPmnXauDNQqLNM7Au0zPceKPnnGK8bUe7ZiK7enSk2iqZsKYaucNzT8Rbgm0Yi2Q8OFQhpGRsdc2qnZH1Ur80vy0JIhl5J/XYdUlN2mYko+bYc3OVFaMWzZuKbD0vGw42adlcT9/wLDt133z4Bg7MOl4Iv7/cAAAAAElFTkSuQmCC" />
					$PercentSharesExPrivP<br>
					<span class="percentagetext2"><span style="color:#9B3722;font-size:12;">$ExcessiveSharesCount</span> of $AllSMBSharesCount</span>
				</span>
			</span>					
	<table>
		 <tr>
			<td class="cardsubtitle" style="vertical-align: top; width:100px;">Read Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentSharesReadP;"></div>
				</div>	
				<span class="cardbartext">$PercentSharesReadP ($SharesWithReadCount of $AllSMBSharesCount)</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Write Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentSharesWriteP;"></div>
				</div>
				<span class="cardbartext">$PercentSharesWriteP ($SharesWithWriteCount of $AllSMBSharesCount)</span>
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">High&nbsp;Risk</td>
			<td align="right">
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentSharesHighRiskP;"></div>
				</div>
				<span class="cardbartext">$PercentSharesHighRiskP ($SharesHighRiskCount of $AllSMBSharesCount)</span>				
			</td>
		 </tr>		 
		</table> 		  
	</div>
 </div>
</a>

<!--  
|||||||||| CARD: ACL SUMMARY
-->

<a href="#" id="AclLink" onClick="radiobtn = document.getElementById('ACLsum');radiobtn.checked = true;">
 <div class="card">	
	<div class="cardtitle">
		Share ACLs<br>
		<span class="cardsubtitle2">configured with excessive privileges</span>
	</div>
	<div class="cardcontainer" align="center">	
			<span class="piechartAcls">
				<span class="percentagetext">
					<div class="percentagetextBuff"></div>
                    <img style ="padding-top:20px; padding-bottom:5px;border-bottom:1px solid #ccc; padding-left:10px; padding-right:10px;"  src="data:image/png;base64, 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" />
					$PercentAclExPrivP<br>
					<span class="percentagetext2"><span style="color:#9B3722;font-size:12;">$ExcessiveSharePrivsCount</span> of $ShareACLsCount</span>
				</span>
			</span>		
	<table>
		 <tr>
			<td class="cardsubtitle" style="vertical-align: top; width:100px;">Read Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentAclReadP;"></div>
				</div>	
				<span class="cardbartext">$PercentAclReadP  ($AclWithReadCount of $ShareACLsCount)</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Write Access</td>
			<td align="right">				
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentAclWriteP;"></div>
				</div>
				<span class="cardbartext">$PercentAclWriteP ($AclWithWriteCount of $ShareACLsCount)</span>
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">High&nbsp;Risk</td>
			<td align="right">
				<div class="cardbarouter">
					<div class="cardbarinside" style="width: $PercentAclHighRiskP;"></div>
				</div>
				<span class="cardbartext">$PercentAclHighRiskP ($AclHighRiskCount of $ShareACLsCount)</span>				
			</td>
		 </tr>		 
		</table> 		  
	</div>
 </div>
 </a>
 <!-- <div style="border-bottom:1px solid #DEDFE1;height: 1px;width:100%"></div> -->
</div>

<!--  
|||||||||| PAGE: COMPUTER SUMMARY
-->

<input class="tabInput"  name="tabs" type="radio" id="computersummary"/>
<label class="tabLabel" onClick="updateTab('computersummary',false)" for="computersummary"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">$TargetDomain  </span> <span class="PageTitleSub">Computer Summary</span><br>	
Below is a summary of the domain computers that were targeted, connectivity to them, and the number that are hosting potentially insecure SMB shares.
</p>
	
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th>Description</th>
      <th align="left">Percent Chart</th>	  
	  <th align="left">Percent</th>
	  <th align="left">Computers</th>
	  <th align="left">Details</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>DISCOVERED</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: 100%;"></div></div></td>
	  <td>100.00%</td>
	  <td>$ComputerCount</td>
      <td><a href="$DomainComputersFile"><span class="cardsubtitle">CSV</a> | </span><a href="$DomainComputersFileH"><span class="cardsubtitle">HTML</span></a></td>	  
    </tr>
    <tr>
      <td>PING RESPONSE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerPingP;"></div></div></td>
      <td>$PercentComputerPingP</td>	
	  <td>$ComputerPingableCount</td>  
      <td><a href="$ComputersPingableFile"><span class="cardsubtitle">CSV</a> | </span><a href="$ComputersPingableFileH"><span class="cardsubtitle">HTML</span></a></td>		  
    </tr>
    <tr>
      <td>PORT 445 OPEN</td>
      <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerPortP;"></div></div></td>
	  <td>$PercentComputerPortP</td>
	  <td>$Computers445OpenCount</td>
      <td><a href="$Computers445OpenFile"><span class="cardsubtitle">CSV</a> | </span><a href="$Computers445OpenFileH"><span class="cardsubtitle">HTML</span></a></td>  
    </tr>
    <tr>
      <td>HOST SHARE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerWitShareP;"></div></div></td>
      <td>$PercentComputerWitShareP</td>	
	  <td>$AllComputersWithSharesCount</td>  
      <td><a href="$AllSMBSharesFile"><span class="cardsubtitle">CSV</a> | </span><a href="$AllSMBSharesFileH"><span class="cardsubtitle">HTML</span></a></td> 
    </tr>
    <tr>
      <td>HOST NON-DEFAULT SHARE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerNonDefaultP;"></div></div></td>
      <td>$PercentComputerNonDefaultP</td>	
	  <td>$ComputerwithNonDefaultCount</td>  
      <td><a href="$SharesNonDefaultFile"><span class="cardsubtitle">CSV</a> | </span><span class="cardsubtitle">HTML</span></td>  
    </tr>	
    <tr>
      <td>HOST POTENITIALLY INSECURE SHARE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width:$PercentComputerNonDefaultP;"></div></div></td>
      <td>$PercentComputerNonDefaultP</td>	
	  <td>$ComputerWithExcessive</td>  
      <td><a href="$ExcessiveSharePrivsFile"><span class="cardsubtitle">CSV</a> | </span><span class="cardsubtitle">HTML</span></td>  
    </tr>	
    <tr>
      <td>HOST READABLE SHARE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerReadP;"></div></div></td>
      <td>$PercentComputerReadP</td>	  
	  <td>$ComputerWithReadCount</td>	  
      <td><a href="$SharesWithReadFile"><span class="cardsubtitle">CSV</a> | </span><span class="cardsubtitle">HTML</span></td>	  
    </tr>
	<tr>
      <td>HOST WRITEABLE SHARE</td>
      <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerWriteP;"></div></div></td>
	  <td>$PercentComputerWriteP</td>
	  <td>$ComputerWithWriteCount</td>	  	  
	  <td><a href="$SharesWithWriteFile"><span class="cardsubtitle">CSV</a> | </span><span class="cardsubtitle">HTML</span></td>	  
    </tr>
	<tr>
      <td>HOST HIGH RISK SHARE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentComputerHighRiskP;"></div></div></td>     
	  <td>$PercentComputerHighRiskP</td>
	  <td>$ComputerwithHighRisk</td>	  	 
	  <td><a href="$SharesHighRiskFile"><span class="cardsubtitle">CSV</a> | </span><span class="cardsubtitle">HTML</span></td>
    </tr>	
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: SHARE SUMMARY
-->

<input class="tabInput"  name="tabs" type="radio" id="sharesum"/>
<label class="tabLabel" onClick="updateTab('sharesum,false)" for="sharesum"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">$TargetDomain  </span> <span class="PageTitleSub">Share Summary</span><br>	
Below is a summary of the SMB shares discovered on computers associated with the target domain that may provide excessive privileges to standard domain users. 
<br>
</p>

<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th>Description</th>
      <th align="left">Percent Chart</th>	  
	  <th align="left">Percent</th>
	  <th align="left">Shares</th>
	  <th align="left">Details</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>DISCOVERED</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: 100%;"></div></div></td>
	  <td>100.00%</td>
	  <td>$AllSMBSharesCount</td>
      <td><a href="$AllSMBSharesFile">Download</a></td>	  
    </tr>
    <tr>
      <td>NON-DEFAULT</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentSharesNonDefaultP;"></div></div></td>
      <td>$PercentSharesNonDefaultP</td>	
	  <td>$SharesNonDefaultCount</td>  
      <td><a href="$SharesNonDefaultFile">Download</a></td>	  
    </tr>	
    <tr>
      <td>POTENTIALLY EXCESSIVE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentSharesExPrivP;"></div></div></td>
      <td>$PercentSharesExPrivP</td>	
	  <td>$ExcessiveSharesCount</td>  
      <td><a href="$ExcessiveSharePrivsFile">Download</a></td>	  
    </tr>
    <tr>
      <td>READ ACCESS</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentSharesReadP;"></div></div></td>
      <td>$PercentSharesReadP</td>	  
	  <td>$SharesWithReadCount</td>	  
      <td><a href="$SharesWithReadFile">Download</a></td>	  
    </tr>
	<tr>
      <td>WRITE ACCESS</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentSharesWriteP;"></div></div></td>     
	  <td>$PercentSharesWriteP</td>
	  <td>$SharesWithWriteCount</td>	  	 
	  <td><a href="$SharesWithWriteFile">Download</a></td>	  
    </tr>
	<tr>
      <td>HIGH RISK</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentSharesHighRiskP;"></div></div></td>     
	  <td>$PercentSharesHighRiskP</td>
	  <td>$SharesHighRiskCount</td>	  	 
	  <td><a href="$SharesHighRiskFile">Download</a></td>
    </tr>	
  </tbody>
</table>
    <div class="pageDescription">
    Note: All Windows systems have a c$ and admin$ share configured by default.  A a result, the number of visible shares should be (at a minimum) double the number of the computers found with port 445 open. In this case, $Computers445OpenCount computers were found with port 445 open, so we would expect to discover approximetly $MinExpectedShareCount or more shares.
    </div>
</div>

<!--  
|||||||||| PAGE: ACL SUMMARY
-->

<input class="tabInput"  name="tabs" type="radio" id="ACLsum"/>
<label class="tabLabel" onClick="updateTab('ACLsum',false)" for="ACLsum"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">$TargetDomain  </span> <span class="PageTitleSub">Share ACL Entries Summary</span><br>	
Below is a summary of the SMB share ACL entries discovered on computers associated with the target domain that may provide excessive privileges to standard domain users.
</p>

<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th>Description</th>
      <th align="left">Percent Chart</th>	  
	  <th align="left">Percent</th>
	  <th align="left">ACLs</th>
	  <th align="left">Details</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>DISCOVERED</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: 100%;"></div></div></td>
	  <td>100.00%</td>
	  <td>$ShareACLsCount</td>
      <td><a href="$ShareACLsFile">Download</a></td>	  
    </tr>	
    <tr>
      <td>NON-DEFAULT</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentAclNonDefaultP;"></div></div></td>
      <td>$PercentAclNonDefaultP</td>	
	  <td>$AclNonDefaultCount</td>  
      <td><a href="$SharesNonDefaultFile">Download</a></td>	  
    </tr>		
    <tr>
      <td>POTENTIALLY EXCESSIVE</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentAclExPrivP;"></div></div></td>
      <td>$PercentAclExPrivP</td>	
	  <td>$ExcessiveSharePrivsCount</td>  
      <td><a href="$ExcessiveSharePrivsFile">Download</a></td>	  
    </tr>
    <tr>
      <td>READ ACCESS</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentAclReadP;"></div></div></td>
      <td>$PercentAclReadP</td>	  
	  <td>$AclWithReadCount</td>	  
      <td><a href="$SharesWithReadFile">Download</a></td>	  
    </tr>
	<tr>
      <td>WRITE ACCESS</td>
      <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentAclWriteP;"></div></div></td>
	  <td>$PercentAclWriteP</td>
	  <td>$AclWithWriteCount</td>	  	  
	  <td><a href="$SharesWithWriteFile">Download</a></td>	  
    </tr>
	<tr>
      <td>HIGH RISK</td>
	  <td><div class="divbarDomain"><div class="divbarDomainInside" style="width: $PercentAclHighRiskP;"></div></div></td>     
	  <td>$PercentAclHighRiskP</td>
	  <td>$AclHighRiskCount</td>	  	 
	  <td><a href="$SharesHighRiskFile">Download</a></td>
    </tr>	
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: GROUP STATS
-->

<input class="tabInput"  name="tabs" type="radio" id="accounts"/> 
<label class="tabLabel" onClick="updateTab('accounts',false)" for="accounts"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Data Insights: </span> <span class="PageTitleSub">Group Stats</span><br>	
This section contains data insights that could be helpful when planning a prioritizing remediation efforts. Excessive Access Summary by Group
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th align="left">Name</th>
      <th align="left">Excessive ACL Entries</th>
      <th align="left">Affected Computers</th>
	  <th align="left">Affected Shares</th>
	  <th align="left">Affected ACLs</th>	 	 
    </tr>
  </thead>
  <tbody>
	<tr>
	  <td>Everyone</td>	
      <td>
 	  <span class="tablecolinfo">
		  <div class="AclEntryWrapper">
			<div class="AclEntryLeft">
			Read<br> 
			Write<br> 
			High Risk<br> 
			</div>
			<div class="AclEntryRight">
			 : $AceEveryoneAclReadCount <br> 
			 : $AceEveryoneAclWriteCount <br>
			 : $AceEveryoneAclHRCount 
			</div>
		  </div>
	  </span>
      </td>		  
	  <td>
		  <span class="dashboardsub2">$AceEveryoneComputerCountPS ($AceEveryoneComputerCount of $ComputerCount)</span>
		  <br>
		  <div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceEveryoneComputerCountPS;"></div>
		  </div>
      </td>     	 	  
	  <td>
		<span class="dashboardsub2">$AceEveryoneShareCountPS ($AceEveryoneShareCount of $AllSMBSharesCount)</span>
		<br>
		<div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceEveryoneShareCountPS;"></div>
		</div>
      </td>  	  
	  <td>
	  <span class="dashboardsub2">$AceEveryoneAclPS ($AceEveryoneAclCount of $ShareACLsCount)</span>
      <br>
      <div class="divbarDomain"><div class="divbarDomainInside" style="width: $AceEveryoneAclPS;"></div></div>
      </td>    	  
    </tr>	
	<tr>
	  <td>BUILTIN\Users</td>		
      <td>
 	  <span class="tablecolinfo">
		  <div class="AclEntryWrapper">
			<div class="AclEntryLeft">
			Read<br> 
			Write<br> 
			High Risk<br> 
			</div>
			<div class="AclEntryRight">
			 : $AceUsersAclReadCount <br> 
			 : $AceUsersAclWriteCount <br>
			 : $AceUsersAclHRCount 
			</div>
		  </div>
	  </span>
      </td>  
	  <td>
		  <span class="dashboardsub2">$AceUsersComputerCountPS ($AceUsersComputerCount of $ComputerCount)</span>
		  <br>
		  <div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceUsersComputerCountPS;"></div>
		  </div>
      </td>     	 	  
	  <td>
		<span class="dashboardsub2">$AceUsersShareCountPS ($AceUsersShareCount of $AllSMBSharesCount)</span>
		<br>
		<div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceUsersShareCountPS;"></div>
		</div>
      </td>  	  
	  <td>
	  <span class="dashboardsub2">$AceUsersAclPS ($AceUsersAclCount of $ShareACLsCount)</span>
      <br>
      <div class="divbarDomain"><div class="divbarDomainInside" style="width: $AceUsersAclPS;"></div></div>
      </td>    	  
    </tr>	
	<tr>
	  <td>NT AUTHORITY\Authenticated Users</td>
      <td>
 	  <span class="tablecolinfo">
		  <div class="AclEntryWrapper">
			<div class="AclEntryLeft">
			Read<br> 
			Write<br> 
			High Risk<br> 
			</div>
			<div class="AclEntryRight">
			 : $AceAuthenticatedUsersAclReadCount <br> 
			 : $AceAuthenticatedUsersAclWriteCount <br>
			 : $AceAuthenticatedUsersAclHRCount 
			</div>
		  </div>
	  </span>
      </td>		  
	  <td>
		  <span class="dashboardsub2">$AceAuthenticatedUsersComputerCountPS ($AceAuthenticatedUsersComputerCount of $ComputerCount)</span>
		  <br>
		  <div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceAuthenticatedUsersComputerCountPS;"></div>
		  </div>
      </td>     	 	  
	  <td>
		<span class="dashboardsub2">$AceAuthenticatedUsersShareCountPS ($AceAuthenticatedUsersShareCount of $AllSMBSharesCount)</span>
		<br>
		<div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceAuthenticatedUsersShareCountPS;"></div>
		</div>
      </td>  	  
	  <td>
	  <span class="dashboardsub2">$AceAuthenticatedUsersAclPS ($AceAuthenticatedUsersAclCount of $ShareACLsCount)</span>
      <br>
      <div class="divbarDomain"><div class="divbarDomainInside" style="width: $AceAuthenticatedUsersAclPS;"></div></div>
      </td>    	  
    </tr>	
	<tr>
	  <td>Domain Users</td>	
      <td>
 	  <span class="tablecolinfo">
		  <div class="AclEntryWrapper">
			<div class="AclEntryLeft">
			Read<br> 
			Write<br> 
			High Risk<br> 
			</div>
			<div class="AclEntryRight">
			 : $AceDomainUsersAclReadCount <br> 
			 : $AceDomainUsersAclWriteCount <br>
			 : $AceDomainUsersAclHRCount 
			</div>
		  </div>
	  </span>
      </td>	  
	  <td>
		  <span class="dashboardsub2">$AceDomainUsersComputerCountPS ($AceDomainUsersComputerCount of $ComputerCount)</span>
		  <br>
		  <div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceDomainUsersComputerCountPS;"></div>
		  </div>
      </td>     	 	  
	  <td>
		<span class="dashboardsub2">$AceDomainUsersShareCountPS ($AceDomainUsersShareCount of $AllSMBSharesCount)</span>
		<br>
		<div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceDomainUsersShareCountPS;"></div>
		</div>
      </td>  	  
	  <td>
	  <span class="dashboardsub2">$AceDomainUsersAclPS ($AceDomainUsersAclCount of $ShareACLsCount)</span>
      <br>
      <div class="divbarDomain"><div class="divbarDomainInside" style="width: $AceDomainUsersAclPS;"></div></div>
      </td>    	  
    </tr>
	<tr>
	  <td>Domain Computers</td>	
      <td>
 	  <span class="tablecolinfo">
		  <div class="AclEntryWrapper">
			<div class="AclEntryLeft">
			Read<br> 
			Write<br> 
			High Risk<br> 
			</div>
			<div class="AclEntryRight">
			 : $AceDomainComputersAclReadCount <br> 
			 : $AceDomainComputersAclWriteCount <br>
			 : $AceDomainComputersAclHRCount 
			</div>
		  </div>
	  </span>
      </td>	  
	  <td>
		  <span class="dashboardsub2">$AceDomainComputersComputerCountPS ($AceDomainComputersComputerCount of $ComputerCount)</span>
		  <br>
		  <div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceDomainComputersComputerCountPS;"></div>
		  </div>
      </td>     	 	  
	  <td>
		<span class="dashboardsub2">$AceDomainComputersShareCountPS ($AceDomainComputersShareCount of $AllSMBSharesCount)</span>
		<br>
		<div class="divbarDomain">
			<div class="divbarDomainInside" style="width: $AceDomainComputersShareCountPS;"></div>
		</div>
      </td>  	  
	  <td>
	  <span class="dashboardsub2">$AceDomainComputersAclPS ($AceDomainComputersAclCount of $ShareACLsCount)</span>
      <br>
      <div class="divbarDomain"><div class="divbarDomainInside" style="width: $AceDomainComputersAclPS;"></div></div>
      </td>    	  
    </tr>
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: SHARE NAMES
-->

<input class="tabInput"  name="tabs" type="radio" id="ShareName"/> 
<label class="tabLabel" onClick="updateTab('ShareName',false)" for="ShareName"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Data Insights: </span> <span class="PageTitleSub">$SampleSum Most Common Share Names</span><br>	
This section contains data insights that could be helpful when planning a prioritizing remediation efforts. 
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>      
      <th align="left">Share Count</th> 
      <th align="left">Share Name</th>
      <th align="left">Affected Computers</th>
	  <th align="left">Affected Shares</th>
	  <th align="left">Affected ACLs</th>	 	 
    </tr>
  </thead>
    <tbody>
    $CommonShareNamesTopStringT
    </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: SHARE OWNERS
-->
<input class="tabInput"  name="tabs" type="radio" id="ShareOwner"/> 
<label class="tabLabel" onClick="updateTab('ShareOwner',false)" for="ShareOwner"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Data Insights: </span> <span class="PageTitleSub">$SampleSum Most Common Share Owners</span><br>	
This section contains data insights that could be helpful when planning a prioritizing remediation efforts. 
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th align="left">Share Count</th> 
      <th align="left">Owner</th>
      <th align="left">Affected Computers</th>
	  <th align="left">Affected Shares</th>
	  <th align="left">Affected ACLs</th>	 	 
    </tr>
  </thead>
  <tbody>
  $CommonShareOwnersTop5StringT	
  </tbody>
  </table>
</div>

<!--  
|||||||||| PAGE: SHARE FOLDERS
-->

<input class="tabInput"  name="tabs" type="radio" id="ShareFolders"/> 
<label class="tabLabel" onClick="updateTab('ShareFolders',false)" for="ShareFolders"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Data Insights: </span> <span class="PageTitleSub">$SampleSum Most Common Share Folder Groups</span><br>	
This section contains data insights that could be helpful when planning a prioritizing remediation efforts. 
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>
      <th align="left">Share Count</th>  
      <th align="left">File Group</th>
      <th align="left">File Count</th>
      <th align="left">File List</th>
      <th align="left">Affected Computers</th>
	  <th align="left">Affected Shares</th>
	  <th align="left">Affected ACLs</th>	 	 
    </tr>
  </thead>
  <tbody>
  $CommonShareFileGroupTopString	
  </tbody>
</table>

</div>

<!--  
|||||||||| PAGE: Exploit Shares
-->

<input class="tabInput"  name="tabs" type="radio" id="Attacks"/> 
<label class="tabLabel" onClick="updateTab('Attacks',false)" for="Attacks"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Recommendations:</span> <span class="PageTitleSub">Exploit Share Accesss</span><br>	
Below are some tips for getting started on exploiting share access.	
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>	  
	  <th align="left">Share</th>
	  <th align="left">Access</th>	  
	  <th align="left">Instructions</th>	
    </tr>
  </thead>
  <tbody>  			
    <tr>	
	  <td>C$, admin$</td>
	  <td>READ</td>
	  <td>
	  Read OS and Application password files and log in.<br>
	  Identify non-public information disclosure.
	  </td>  
    </tr>	
    <tr>	
	  <td>C$, admin$</td>
	  <td>WRITE</td>
	  <td>Read OS and Application password files and log in.<br>
	  Identify non-public information disclosure.<br>
	  Execute arbitrary code by writing files to autorun locations:<br>
	  DLL Hijacking<br>
	  All Users folders<br>
	  Other file based autoruns<br>
	  EXE Replacement<br>
	  </td>  
    </tr>	
   <tr>
	  <td>wwwroot,inetpub,webroot</td>
	  <td>READ</td>
	  <td>Read connection strings and escalation through database. <br>
	  <span class="code">Code - search for file types</span><br>
	  <span class="code">Code - search for file contents</span><br>
     </td>    
   </tr>
   <tr>
	  <td>wwwroot,inetpub,webroot</td>
	  <td>Write</td>
	  <td>
	  Read connection strings and escalation through database.<br>
	  Upload webshell to execute as web server service account.
	  </td> 	  
    </tr>				
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: Detect Share Scan
-->

<input class="tabInput"  name="tabs" type="radio" id="Detections"/> 
<label class="tabLabel" onClick="updateTab('Detections',false)" for="Detections"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Recommendations: </span> <span class="PageTitleSub">Detect Share Enumeration</span><br>	
Below are some tips for getting started on building detections for potentially malicious share scanning events.
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>	  
	  <th align="left">Action</th>
	  <th align="left">Detection Guidance</th>	  
    </tr>
  </thead>
  <tbody>  	    
   <tr>
	  <td>Detect Share Scanning</td>
	  <td>Build detections for authenticated share scanning.  event 1 and event 2. At min frequency of x y z.
	  </td>  	  
    </tr>
   <tr>
	  <td>Detect Canaries</td>
	  <td>Build detections for authenticated share access read/write access.
	  </td>  	  
    </tr>				
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: Prioritize Remediation
-->

<input class="tabInput"  name="tabs" type="radio" id="Remediation"/> 
<label class="tabLabel" onClick="updateTab('Remediation',false)" for="Remediation"></label>
<div id="tabPanel" class="tabPanel">
<p class="pageDescription">
<span class="PageTitle">Recommendations: </span> <span class="PageTitleSub">Prioritize Remediation</span><br>	
Below are some tips for getting started on prioritizing the remediation of shares configured with excessive privileges.
</p>
<table class="table table-striped table-hover tabledrop">
  <thead>
    <tr>	  
	  <th align="left">Share Access</th>
	  <th align="left">Impact</th>	  
	  <th align="left">Description</th>
    </tr>
  </thead>
  <tbody>  	
    <tr>
	  <td>High Risk Shares</td>
	  <td>Confidentiality, Integrity, Availability, Code Execution<br>
	   High likelihood.
	  </td>
	  <td>Remediate high risk shares. In the context of this report, high risk shares have been defined as shares that provide unauthorized remote access to systems or applications. By default, that includes wwwroot, inetpub, c$, and admin$ shares. However, additional exposures may exist that are not called out beyond that.</td>  
    </tr>	
    <tr>
	  <td>Write Access Shares</td>
	  <td>Confidentiality, Integrity, Availability, Code Execution</td>
	  <td>Remediate shares with write access. Write access to shares may allow an attacker to modify data, insert their own users into configuration files to access applications, or leverage write access to execute code on remote systems.  Folders that provide write access could also fall victem to ransomware attacks.</td>  
    </tr>		
    <tr>
	  <td>Read Access Shares</td>
	  <td>Confidentiality,Code Execution</td>
	  <td>Remediate shares with read access. Read access may provide an attacker with unauthorized access to sensitive data and stored secrets such as passwords and private keys that could be used to gain unauthorized access to systems, applications, and databases.</td>  
    </tr>
    <tr>
	  <td>Top Share Names</td>
	  <td>NA</td>
	  <td>Sub prioritize remediation based on top groups of share names(most common share names). When a large number of systems are configured with the same share, they often represent weak configurations associated with applications and processes.</td>  	  
    </tr>
   <tr>
	  <td>Top Share Groups</td>
	  <td>NA</td>
	  <td>Sub prioritize remediation based on top share groups that have the same list of files in their directory.  This is another way to identify systems that are configured with the same share are associated with the same insecure application deployment or process.
	  </td>  	  
    </tr>		
      <tr>	
	  <td>Sub Prioritzation Tips</td>
	  <td>NA</td>
	  <td>
	  Use the detailed .csv files to:<br><br>
	  1. Identify share owners with the ShareOwner field. Filter out "BUILTIN\Administrators", "NT AUTHORITY\SYSTEM", and "NT SERVICE\TrustedInstaller" to identify potential asset owners.<br><br> 
	  2. Filter out shares with a FileCount of 0.<br><br> 
	  3. Sort shares by LastModifiedDate.<br><br> 
	  4. Filter for keywords in the FileList.<br><br>
	  For example, simple keywords like sql, database, backup, password, etc can help identify additional high risk exposures quickly. <br>
	  </td>  				
  </tbody>
</table>
</div>

<!--  
|||||||||| PAGE: Home
-->

<input class="tabInput"  name="tabs" type="radio" id="home"/> 
<label class="tabLabel" onClick="updateTab('home',false)" for="home"></label>
<div id="tabPanel" class="tabPanel">	
<div style="min-height: 510px">
	  <img style="vertical-align:middle;float: left;clear:both; margin-top: 4px;margin-right: 15px;" src="data:image/png;base64, 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gYUo7RopJlJ0HvPwjzj+JLlkcpXByLGAKlRIjh/8D37P1ixMTbpJwRjQ/WLbH6NAYBdo1m37+9i2myeA/xm40tr+agOY/SS93tYiR0D/NnBx3dbkPeByBxh+0iVDciQ/LaFQAN7P6JtywMAt0Lvmzq11jtMHIEOzWr4BDg6BsSJlr3u8u6dzbv/2tOb3A010cpg8Qkn4AAANGGlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNC40LjAtRXhpdjIiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iCiAgICB4bWxuczpzdEV2dD0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlRXZlbnQjIgogICAgeG1sbnM6ZGM9Imh0dHA6Ly9wdXJsLm9yZy9kYy9lbGVtZW50cy8xLjEvIgogICAgeG1sbnM6R0lNUD0iaHR0cDovL3d3dy5naW1wLm9yZy94bXAvIgogICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iCiAgICB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iCiAgIHhtcE1NOkRvY3VtZW50SUQ9ImdpbXA6ZG9jaWQ6Z2ltcDo4ZDAzMzg4Ni05YWY0LTQ0OGMtODAzZi1mMWNhZjgxMmIzZWQiCiAgIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6Y2Q4NGFlNDEtYTBhYy00YTZjLTllMTEtODI1MDQzMzJlOTBlIgogICB4bXBNTTpPcmlnaW5hbERvY3VtZW50SUQ9InhtcC5kaWQ6OGIzMGZiYmQtMjdlNC00YTZiLTgzNmItZDIzNTA0NWE1MmRkIgogICBkYzpGb3JtYXQ9ImltYWdlL3BuZyIKICAgR0lNUDpBUEk9IjIuMCIKICAgR0lNUDpQbGF0Zm9ybT0iV2luZG93cyIKICAgR0lNUDpUaW1lU3RhbXA9IjE2NDI4MDgwNDk4NzAzMDUiCiAgIEdJTVA6VmVyc2lvbj0iMi4xMC4yOCIKICAgdGlmZjpPcmllbnRhdGlvbj0iMSIKICAgeG1wOkNyZWF0b3JUb29sPSJHSU1QIDIuMTAiPgogICA8eG1wTU06SGlzdG9yeT4KICAgIDxyZGY6U2VxPgogICAgIDxyZGY6bGkKICAgICAgc3RFdnQ6YWN0aW9uPSJzYXZlZCIKICAgICAgc3RFdnQ6Y2hhbmdlZD0iLyIKICAgICAgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo3M2I1MzNhNy1mYzIyLTQxMWYtYWIxNC05NjMxZjc5NWI1OTEiCiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkdpbXAgMi4xMCAoV2luZG93cykiCiAgICAgIHN0RXZ0OndoZW49IjIwMjItMDEtMjFUMTc6MzQ6MDkiLz4KICAgIDwvcmRmOlNlcT4KICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgIAo8P3hwYWNrZXQgZW5kPSJ3Ij8+RAc8WgAAAAZiS0dEAOgA9ABKxSNE4wAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+YBFRciCZFpl1MAACAASURBVHja7b15lF1Xdef/Oefe++Z6NU+a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" />
      <div style="font-size: 14; margin-left: 0px;display:block;height: 100px;overflow: hidden;">
	  <Br>
	  <span class="pagetitlesub" style="font-size:40;">SMB SHARE HUNTER</span>	 
	  <br>
	  <span style="font-size: 20;font-weight:bold;color:#3D3935;">Active Directory Share Excessive Privilege Report</span>
	  <br>
	  
	</div>	
<br>
<div style="border-bottom: 1px solid #DEDFE1 ;  background-color:#f0f3f5; height:5px"></div>

<!--  
|||||||||| CARD: SCAN SUMMARY old
-->

 <a href="#" id="DashLink" onClick="radiobtn = document.getElementById('dashboard');radiobtn.checked = true;">
 <div class="card" style="position:absolute;margin-top:24px;width:260px;">	
	<div class="cardtitle">
		Scan Summary<br>
		<span class="cardsubtitle2">Below is the scan summary</span>
	</div>
	<div class="cardcontainer" align="center">			
	<table>
		 <tr>
			<td class="cardsubtitle" style="vertical-align: top;">Start Time</td>
			<td>					
				<span class="AclEntryRight">$StartTime</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Stop Time</td>
			<td >					
				<span class="AclEntryRight">$EndTime</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Duration</td>
			<td >					
				<span class="AclEntryRight">$RunTime</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Host</td>
			<td >					
				<span class="AclEntryRight">$RunTime</span>				
			</td>
		 </tr>		
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">User</td>
			<td >					
				<span class="AclEntryRight">$username</span>				
			</td>
		 </tr>	
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">Domain</td>
			<td >					
				<span class="AclEntryRight">$TargetDomain</span>				
			</td>
		 </tr>
		 <tr>
			<td class="cardsubtitle" style="vertical-align:top">DC</td>
			<td >					
				<span class="AclEntryRight">$DomainController</span>				
			</td>
		 </tr>		 
		</table> 		  
	</div>
 </div>
</a>

<!-- home text -->
<div style="margin-left:290px;"> 
<br>

<span style="font-size:30; color:#222222; font-weight:bold">How do I use this report?</span>
<br><br>
<div style="width:60%">
The <a  style="color:#333" href="https://github.com/NetSPI/PowerShell/blob/master/Invoke-HuntSMBShares.ps1">Invoke-HuntSMBShares.ps1</a> audit script was run against the $targetdomain domain to collect SMB Share data, generate this HTML summary report, and the associated csv files that detail potentially excessive configurations.
The basic SMB scan context can be found in the table to your left, and other sections are available in the left menu.<br>
<br>
Follow the guidance below to get the most out of this report.
</div>
<br>
<button class="collapsible"><span style="color:#CE112D;">1</span> | Review Reports and Insights</button>
<div class="content">
<div class="landingtext" >
Review the reports and data insights to get a quick feel for the level of SMB share exposure in your environment.
<br><br>
<strong style="color:#333">Reports</strong><br>
The <em>Scan, Computer, Share, and ACL</em> summary sections will provide a  summary of the results.  
<br>
<br>
<strong style="color:#333">Data Insights</strong><br>
The <em>Data Insights</em> sections are intented to highlight natural data groupings that can help centralize and expedite remediation on scale in Active Directory environments.
<br>
</div>
</div>
<button class="collapsible"><span style="color:#CE112D;">2</span> | Review Detailed CSV Files</button>
<div class="content">
<div class="landingtext">
Review potentially excessive share ACL entry details in the associated HTML and CSV files.
</div>
</div>
<button class="collapsible"><span style="color:#CE112D;">3</span> | Verify and Remediate Issues</button>
<div class="content">
<div class="landingtext" >
Follow the guidance in the Exploit Share Access, Detect Share Access, and Prioritize Remediation sections.</div>
</div>
<button class="collapsible"><span style="color:#CE112D;">4</span> | Review Definitions</button>
<div class="content">
<div class="landingtext">
Review the definitions below to ensure you understand what was targeted and how privileges have been qualified as excessive.
<br><br>
<strong style="color:#333">Excessive Privileges</strong><br>
In the context of this report, excessive read and write share permissions have been defined as any network share ACL containing an explicit entry for the <em>"Everyone", "Authenticated Users", "BUILTIN\Users", "Domain Users", or "Domain Computers"</em> groups. 
All provide domain users access to the affected shares due to privilege inheritance. 
<Br><br>
Please note that share permissions can be overruled by NTFS permissions. Also, be aware that testing excluded share names containing the following keywords: <em>"print$", "prnproc$", "printer", "netlogon",and "sysvol"</em>.
<br><br>
<strong style="color:#333">High Risk Shares</strong>
<br>
In the context of this report, high risk shares have been defined as shares that provide unauthorized remote access to a system or application. By default, that includes <em>wwwroot, inetpub, c$, and admin$</em> shares.  However, additional exposures may exist that are not called out beyond that.
<br>
</div>
</div>
<button class="collapsible"><span style="color:#CE112D;">5</span> | Run Scan Again</button>
<div class="content">
<div class="landingtext" style="">
Collect SMB Share data and generate this HTML report by running <a href="https://github.com/NetSPI/PowerShell/blob/master/Invoke-HuntSMBShares.ps1">Invoke-HuntSMBShares.ps1</a> audit script.<br>
The command examples below can be used to identify potentially malicious share permissions. 
<br><br>
<strong style="color:#333">From Domain System</strong>
<div style="border-radius:25px;border: 2px solid #CCC;margin-top:5px;padding: 5px;padding-left: 15px;width:95%;background-color:white;color:#757575;font-family:Lucida, Grande, sans-serif;">
Invoke-HuntSMBShares -Threads 100 -Timeout 10 -OutputDirectory c:\folder\ 
</div>
<br>
<strong style="color:#333">From Non-Domain System</strong>
<div style="border-radius:25px;border: 2px solid #CCC;margin-top:5px;padding: 5px;padding-left: 15px;width:95%;background-color:white;color:#757575;font-family:Lucida, Grande, sans-serif;">
runas /netonly /user:domain\user PowerShell.exe<Br>
Import-Module Invoke-HuntSMBShares.ps1<br>
Invoke-HuntSMBShares -Threads 100 -Timeout 10 -OutputDirectory c:\folder\ -DomainController 10.1.1.1 -Username domain\user -Password password 
</div>
</div>
</div>
<br>
<script>
var coll = document.getElementsByClassName("collapsible");
var i;

for (i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.maxHeight){
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = content.scrollHeight + "px";
    } 
  });
}
</script>
</div>
</div>
</div>
</div>
<!--  
|||||||||| FOOTER
-->

<div style="border-top: 1px solid #DEDFE1 ; background-color:#f0f3f5; height:10px;"></div>
<img style="float: right;margin-right:15px;margin-top:15px;margin-bottom:15px;" src="data:image/png;base64, iVBORw0KGgoAAAANSUhEUgAAAMgAAAAwCAYAAABUmTXqAAAVF3pUWHRSYXcgcHJvZmlsZSB0eXBlIGV4aWYAAHjapZpXdmM5d4XfMQoPAekgDAdxLc/Aw/e3QarcVd0v/VssUdQViXDCDrjlzv/893X/xZf5WFy22kovxfOVe+5x8KL5z9d4z8Hn9/y+1s/fwu/XXfpe95FL+uV7oZXv+3+uh18DfH4MXtlfBmrr+4f5+x96/o7f/hjoO1HSiiIv9neg/h0oxc8fwneA8dmWL73Vv25hns/P/bOT9vl2eooWynewzyr++D1XorcJKVfiSSF5nmNqn/ckfUeXBi/Ce65Rrzqv7T2nFL4rISD/FKdfX50VXS01/+ObfsvKr1d/ZCv9xOjPbOX4fUv6I8jl189/vO6C/XNWXuj/MnNu31fx9+uWQvys6I/o6/ve3e7bM7sYuRDq8t3UzxbfK943mUJTN8fSiq98G0PU9+g8GlW9KIXtl588Vughkq4bcthhhBvO+7nCYok5HhfJVYxxxfQuNnLX43qZzHqEGys53KmR5EXaE1fjr7WEN233y73ZGjPvwFtjYLCguvi3D/dvP3CvWiEExZLUh09+Y1SwWYYyp2feRkbC/QbVXoB/Hn9+Ka+JDJqirBbpBHZ+hpgW/g8J0kt04o3Gz08Phrq/AxAipjYWExIZIGsh0VrB1xhrCASykaDB0mPKcZKBYBY3i4w5pUJuWtTUfKSG99ZokcuO64AZmbBUUiU3dBnJytmon5obNTQsWTazYtWadRsllVyslFKLQHHUVLOrVkuttdVeR0stN2ul1dZab6PHngBN66XX3nrvYzDnYOTBpwdvGGPGmWae5maZdbbZ51iUz8rLVll1tdXX2HGnDX7ssutuu+9xwqGUTj52yqmnnX7GpdRucjdfu+XW226/41fWvmn92+NfZC18sxZfpvTG+itrXK31Z4ggODHljIRFlwMZr0oBBR2VM99CzlGZU858j3SFRRZpytkOyhgZzCdEu+Endy5+MqrM/b/y5mr+LW/xP82cU+r+Zeb+nrd/ytoWDa2XsU8XKqg+0X28h8lHOyOVOczammyCmCzzq9D9uac7eBtBCjuPnXKfoUdGHzX4PVdJcZ0c0u0+LGbz4/hkdd4d54n19F4Jdil9VnKyj/W1TwEQSZ2FdMCKHs5ihNNyJTmjE/Y92ZEViHmdMS12QuXZnjubJPva1l3KyYmdWXwp9GtbJ8Y202Xb4VYWUXnnSaPPlWqNkw+UvBgqt+p62Cemu0+4OxMpqzHUThrDqPvkSbIqqGvkYE8DRoHmnS+U0HnfOGVYsLabW3HHvO6uYDkbiPmWQNKGxVPmtXTOqC2zgm1195Rnj/vuNC/Xd6qeX4axfxcW8VkrQw9tBAF3o5wpxUCH3sWqEjvL1NbNe5Maxsu2GYEu6Q+2yDW8NjelcG3daRDR2KfZ8eP6k5mg7XtmqJd9Nl9yno2qa6R2GfHddA+8QfX7PF2dlP4NpbbkjxSMDYp40l7ntAuiske6++xYJy3ETuaeY5dLvd9eSyICPrTslmdXvteZqVQyMO2eWrXYBp/tyUbiOZsas3kb3WUUIxuOEGVNZ9q5VEq/Lky9YUTCRNOuRmk03hEBlUuF1zB73bOHVcuiaCn/OHdOhw23xNT7ZsAuTmJ0YczQYtnbE+de2XjXikCeTDZbooDp0j3oXAqU9cKwl6acnSYMlOhd87qBXihQQQMy0w1czJRfpPuRZlQW1cOiGkQyCLdvY/sxqflskT6jn6mlyQLdumWNOGNlBipzJ0aiMigpWm3N2XMDEMp+T4fXd1ENRHtIqNJ198RGbByIdVGY3QC1QGkNwkHdHQuLdg0zEog6d83zBCp0tk2Rs7xil7LyBfhps1p3EelDkrVKlDBJZ48x3qatLZD0NGKJWFprR5oqqF0YfkniH8pppuWRKObaVGA9EEB1C3WGr3vr1UGovCt8liqnhrZm8aPR35OrfWTzNd85V0iOLGTE0b3FxqGtK5GiskbpIEEKgJK3sRfdawcKL2Ai0DmIA7rppuJpiVB9cju9acgl2wnaC/D68HRs2jWGvMrp0ejTMgS+fvU4gckCyxCCTgjOztkRKniJwQh2a9Qhl9fN61CLRI2P0LgeDqndAzJpmT5JPEKGUAbTATkUCl6knZwJJVqSoBd66lwSnTofYTup37BsUpdllQh5pbRVlQAdVSn5A9HUiWDflXplCdASVVbXsQEV7bQq6WpggYGRB10zBW+BcNK8RMUyKyMHbZUMLINH4RbwnkXECqJewUgH1SrtykahuTXPCGGuNqgnFn3vHPnUoRYKJDTNcCVrAsWA1p27TzHzLrACH8iB4o+7pG6rQcsT6KeJ1qFOp4F2bAS3wvRqpEXWAErAee8MCxhwWxqjFjUUNmP1g7ifrd1a6aQVSkFi00Z9lgaTUfX66wgOvKM42x3lbLMXukw5xAllUNHqzq04wdmTKkK5wJEZEkEVoWGg63YaxeSMorB2bUPpw8DcTk8++mYoi0YyaR9YLfq7Rm7pXCqzgppaWRtqiHGBWvpnk70ojERmxHKpQW84sIt2oI8ymgg1gqjuKt2ADhD5HnglstAB5KiWsBA0BwDAPmbZKJmLbyzRN5JR9ljEjgqMZe640DFT5UYfp0aNgjwLRIGee3OwvHRWX0D16804fmi3UkfzRpwLOAuWoUHouQ5+1gLj2TqIkwMJcqHi1+isvHBB9HNh93RBowJhlwoPQFooB3h4zkZ7wkDooMfRQDCRoFM3DWNALXB3IL+2QaFqa2fRPsTfhG+thk4X09JqAyiY8FOsm/aCNFcUKF6jtLuzx8FX6mfns5ERcHM+5J05KTYb1vxKxLMvdUDGx0VSCoAEwNhufdA7HUGf14PY7KGKElENBZy98OTY6ASCPOngpsMF6Bw9S3XxyFxkTjVJYXsuiJqp0CDQJH4DFmKO2lGlbU/Kh0JHNQwQD+zOQEq3RvUYE0tZItdG3JWtEZwQpycQ6FRyCqPdtMc8hLcCLxscIswLblw10yLe6JYOCBCspAUTqO3ALYwmX9QliJJIIn/pPa1zcMWybuVIQmdVsm3SJZESaya0gMBYNNfMqNp+ezGEcDmQcVos7jAWAD/p/hxFe1QYPQ/SxAdACA508xyoDljFNp0CZUMABVGcgYWr51Zzp6Fqg92pRN6K7kWJhXYkPlFe2hdCDgpNlA16V0SBYKc0Jpy1NxuJAH9XaQ5E8UWPDdwIgbl0sjhE/G9ATUQuAThyJUtiitQ6mJjhxVNItErplt2prAgxNiBHbQTKDY+3Q5+DySp2qh4FMWEp8AQY2Au/hpJBWSBfi9qD9fibY9RyETzhkPTEFKiBTdtfivGg4uhsUKtvejKhRtFdDs1BuDqjtZb3YhILDfhCXE0tpi+g8Q4U0IrA8r0UWHycPC4pvBeJt2EARy8ESNXLMdm+yq2NV/vT41BSL/lGOiaCft1ACsJ4MAqFDARFGxcVF+5o4X4y2Y25/rY9Kjqx9QoTLMZAwW4jfABQKhV6oxiReQgtJDA84F2VbklDcPPRtgnVBOkSdSSIYdkRsQdiJuS0DMDdigciJTXQglGGRycyDm5qwMh9/nNLwCCWnkKBfEz0j1qEixH9oBT9xLMBJ6puvQtMZpp7HfoXJf6Ch8xGvi7/homRCnha0g6Noiv4PWgpDlXtvQRt6oN1bIXcURXVBINiBPQeOoXPY+BAg3p7gIkjKgusp0OBpDpB5D0eI6MA0PfrTeMEEtiJg+5ATmaRIMIJvYQIP3OSY5lQMp2jpFDGMlzCCPPMcucB34T2dtxI0g+o2WCKRRfHaga8KAuu0fBG8CV/E6Ote6l/4UwlDGiy50MA5eIEcucdqSFvhgyhf+UmOzM/MVqSrtQNFHtHQJjYTeIZ1Zj6gy5bx0H3ETUEzQrIkbTUJspqs3VgkNRW8BYZJoNjFD8YVwi21zawmhf3r1Aeh+maW5fNTjhqVyARFCgT0c6lihUEVIjNwFWsAGHJf9cTRLL001p9kkG2ttluoKYlsqC42qT+xSt0xp1g2dm4pJE+rA6owHy4dugiEH87CDJ6zIn8QNF1INKINwIaGz0VKL2RASAyxFT4W5Y/UgfIB76LEuALNWMmcMK1OZn8wBbC+RQiYi3V9wppUkFNYo6YA02OrDieH0lBpOUCJt+9nQ02F8fKF7xHx4VMiyM/QDMaiQkG1WWGp4pdqgbZmjQjeDEzYl7AC/3CNoltOPGViTMAZ1nwiQxGFCbsjI4KruSaFDjBBVXQSvTyngQrlSg0DejC3mdwu3l4R4pn0aKEnkhDnxWRR+RZzVy+MdeeGXez2SCBIm6UCZuErEPb1Ja58mnILGUAboT4inDITYOPC+6mSu5IH0xUt+BEKX9mmYXANuwwIJtc3IKNA83Qk0hXVobtnJUERLEyqJGlCQQhRPn0LPEGhFBJ/GbPgqMCGGgBtAU1c8g5zIcJPB5tTqmEerBd6E6UPjUu+TI0uJp6dMkE6b+tXOIgOz4HIUSd0DPBiCLKMeBiYXi/8TSAWsUleWidGAMwgYqeKI2pIw50P16iBkfCASBKmi0GeqFElNzCi2FxSMLoAvd8sk4bM3WP7OWhgzWlSxVqXvlxpBZ10FJIbBgNOKCQjppBjGM4MJ3AiVbPcuYtA53C3vgkYmuneNBzWP8+zFFvgJA0TaF4dH4nBzobG9VB1O0wPIVaEUhAwt5RPgVjoUOXTMKQKaizPBwGHkt2I4MUvlKXL8Dlk9xa+/fwB4ULGszv4U/HxpN3qAHiWBgEwD67gRW82lJE5SAo6ZeKIt7Y0/Vxu8yBkGE/nnhULDbyTsezDJ1UIvwCHruZF4a60NMddGNNGEisg+6b8DlCFnSQpAOttFbyix578YKQMjpncRlPS7BNttJTIOwaVa7DtIqGz7Mh8S8oTZFjpslblR3IsFjTWQFQDDHoOGoQmRIka/B8DD1yCgvR9bntsYT+GNpcZxgLZLbb+CQxgrvQnSiWoVMOcPSRaXQY4nGBEoi2ycPB8u3Iz9bg5Q42+vdmNTA+okMOUJL61VP/4oTP96Rpb2p0lgJnVf2yQVW40qIu0nQXwZagUQgDdDpRWgBBNNLWIT4oFNgrLeIRqDh55qgoLLlULAFeAQ0Ng6BN5gYE4E9sJVMiSWLY2MEG/tBrlDKQdGdzlz1XqpWWQOfcd37CdsOV74F9l0ABhStBBO7I00Y0WmH9z7ezoIzDS273BSazKbhjoZylLLM4F68t+XEFWDvgh2ETkBYhcS/dJjoD5kTuRL3gIHtHjlW609OIPstroGgQiOBgFK2xigA5K+uUP2KYNctzZTwCRkJ3oMbCHMf6uU+3fRVGSy1GdcLwOjwTW6LXkVe478VnBdPMBkf6LyGosM5yeYN4gNJB+wEntA5giTZjTbCurdUimmBtnfLqBiYiGT0SfG2KrunGC1ttzc3xNgvSYKIn3YBgoQo7TKvWwq4ZcNEhDNIU5X4zFYvHJCOwXc9vJPQRg/02Vo94RnvnP8KXE5EqQJt0E+Zmd5ksgSIl13QKpolREtQRGMowXtBOsmgOnkF+AAy1cWh9sAKIoWZSQpMgW3H0T7t5nSCxBYnM4GipliThkCjvPNTv+HMghjr17zyUl+AG2Hsok0xYseWoAlxshrF1upLdHQQfKQJTVerqRA2c0apFZ2kacgt8dP9lg27/JO+euHO6wfx3fQcZ/qnwpO9+yTvA6q8CD0xxT9/9Xd2hoEyiVSeJHRpge4h0oBR/ixmYCZnMBuE/9G/G/DjI4jTReH2q1DDmLyhAEKNNMGxjBTq592PGbis3otN1HCw+wvnBr2hHx5bQW1dnmQO5scD4GYFzdCb91bFKeErd0WDJiEV4PzQtkozDoWsPxDv0V12H0VqWBdoyku/gjHhvAFqShQjam9Uewq1ChSLtWQm+ZEckJe6RFS3HL22ROZvvfxtgPXHL9YorS5MPwGRPGkdHAzZBNRofA03rdtjGF3Qh7ExlH0yspEfQ0Sfhotcoa0tGp5EVlBW2OLPlUeLVCT/QvdbnNg2Wh49gVcA318EdwomJBSJ7x6vRp5J8HU25KD9sG01+5Kalc719tD7V9LFCd0xMRHFX9UsFrdi2flLi9yNG8YrvhotWWsVYDQEM2pJ1bXeUDHkCDyAjnsRBTh6e77rB2zCjwaRk2NibGR4D/j9m636mQSaimzwpXA3ofLUPYLjPZoUYHxv3zoA8YDBX/3Fx2g8gj0dL+JzPsJ+OzMoJEhi/xgJMpwUxvPtmtZNg7HZRD2JWq+iiE2JQvetGlJV5ms7m0bk62JdxQZrDa9QJMcTfpEg1jiahf6kwUQAZANfX0jE96C38zHQexIHRxtmmUigc9hyuA32r/gfIRXLI4yO3HkhQ+AcYP1HGDq7Di5MDCTdCnCNKcaMpLposvPs5Tox4HmY0OBWFPTeNZaC0bpss3SJrFA4ZiMsPnRQDEIQO7iV1ig4FELo5s+DfmYnpP1AExpAg+V17jiXtKfT+as8cI7Ox8aVDuKvjMOQxiZ3GP0wz2Dol0hNxRuqFxN5YcQnvvuiVWK3g09Kh8Z4NVljMN1Bl0S3dCASjWlk6ezoSczSITmQ96xqna0KURcC7DeZssyPC6Z1NOy1sASWIAnBkUAfsA4ABmqS0LfOJ27uOsKfutlhUjRiEODsufnnDUYN5wBlkmNDygJeLJB2wIpGW3/mg+PboXtK7pfN+ovuVdtEmPc2nch+N/YNaqCQAfpK1IrkogzmwvynRUUkQQySyToGBeB0W4w2kNGB3RQsiBAg7aIBWB1KpqOw2cpPaM58qIN1pxKs7TxFuR7gVhID4Ly+1734y755HW1dwIAHImPzVkaR3G0fHPPQhXJmoU1Fk010isEG3r0ub0n1ILGqdRqDa7+TzswK/0Ga5DgZG9OLI2ucmQhNgYJRDQOKbzvtwfOWwRGzm7qnquOegW71OorduylLXNbp3uxcAHzomiNfijbAboqFSf0NQxHPTfUO8WyMNReG/YTMrvVwQ/UUnrk4yNC4drtgoMuxAJloecGg6CMUfo1zQWknm6ekr3RYl/ZU+QVJENpGIqUO5D2w/9kS39HVDyKtc4Onl09BZsoA7UfqfikFnwRxhgi9eB+G4aEpmdvdnzUgooPt19llQkWmiiUDhxmoi3nVNuoTFLd0YJg+GhNIxy3a7iuvQnRiHVlgm9IJcNxyO/lObalrHyRA1lPO/WiaW32E/9tkAAAGFaUNDUElDQyBwcm9maWxlAAB4nH2RO0jDUBSG/6ZKi1Qc7CDikKE6WRCVIk5SxSJYKG2FVh1MbvqCJg1Jiouj4Fpw8LFYdXBx1tXBVRAEHyCOTk6KLlLiuUmhRYwHDvfjv+c/nHsuIDSrTDV7JgBVs4x0Ii7m8qti4BU+BClnEZOYqSczi1l4xtc9VVLcRXkv77o/o18pmAzwicRzTDcs4g3i2Kalc94nDrOypBCfE48bNCDxI9dll984lxwWeM+wkU3PE4eJxVIXy13MyoZKPE0cUVSN+gs5lxXOW5zVap215+QvDBW0lQzXKUeQwBKSSEGEjDoqqMJClE6NFBNpuo97+Icdf4pcMrkqYORYQA0qJMcP/ge/d2sWpybdTqE40Pti2x+jQGAXaDVs+/vYtlsngP8ZuNI6/loTmPkkvdHRIkfAwDZwcd3R5D3gcgcYetIlQ3IkP6VQLALvZ/RNeWDwFuhbc/fWvsfpA5ClXS3fAAeHwFiJeq97vDvYvbd/a9r7+wG/gHLG4Z+wOAAADRhpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+Cjx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDQuNC4wLUV4aXYyIj4KIDxyZGY6UkRGIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyI+CiAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIKICAgIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIKICAgIHhtbG5zOkdJTVA9Imh0dHA6Ly93d3cuZ2ltcC5vcmcveG1wLyIKICAgIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIgogICAgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIgogICB4bXBNTTpEb2N1bWVudElEPSJnaW1wOmRvY2lkOmdpbXA6YTA3MzljMzctNTU1YS00OTJlLWJjMTYtZjMyMzVkMjg5OWExIgogICB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOmJmNDBhODBjLThlZjgtNGMwMi1hMGNjLWJiY2UzYjFhZWIxYSIKICAgeG1wTU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOjhkZjFlZGY5LWUwMTItNGU5MC1hMDY1LWY1ZTYwN2NmNTcwZiIKICAgZGM6Rm9ybWF0PSJpbWFnZS9wbmciCiAgIEdJTVA6QVBJPSIyLjAiCiAgIEdJTVA6UGxhdGZvcm09IldpbmRvd3MiCiAgIEdJTVA6VGltZVN0YW1wPSIxNjQxNjA3MTczMTYwNjAwIgogICBHSU1QOlZlcnNpb249IjIuMTAuMjgiCiAgIHRpZmY6T3JpZW50YXRpb249IjEiCiAgIHhtcDpDcmVhdG9yVG9vbD0iR0lNUCAyLjEwIj4KICAgPHhtcE1NOkhpc3Rvcnk+CiAgICA8cmRmOlNlcT4KICAgICA8cmRmOmxpCiAgICAgIHN0RXZ0OmFjdGlvbj0ic2F2ZWQiCiAgICAgIHN0RXZ0OmNoYW5nZWQ9Ii8iCiAgICAgIHN0RXZ0Omluc3RhbmNlSUQ9InhtcC5paWQ6YjMwNGFjZDAtYmYwOS00ZTg4LTlkYmYtMGRiZjI3N2JjNTM5IgogICAgICBzdEV2dDpzb2Z0d2FyZUFnZW50PSJHaW1wIDIuMTAgKFdpbmRvd3MpIgogICAgICBzdEV2dDp3aGVuPSIyMDIyLTAxLTA3VDE5OjU5OjMzIi8+CiAgICA8L3JkZjpTZXE+CiAgIDwveG1wTU06SGlzdG9yeT4KICA8L3JkZjpEZXNjcmlwdGlvbj4KIDwvcmRmOlJERj4KPC94OnhtcG1ldGE+CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAKPD94cGFja2V0IGVuZD0idyI/PtS9HRQAAAAGYktHRADoAPQASsUjROMAAAAJcEhZcwAALEoAACxKAXd6dE0AAAAHdElNRQfmAQgBOyGFBMYxAAAPlElEQVR42u2de5QU1Z3HP7d7eJno6syIJAgm7lndaOyZXqzBGgrMyksUlYeQGBXFF+pKkFVWIkkEY9yNCRBU1N1g1rgKCEpAI+tBQIGCilNoQ2seLCFGlJFXTyBBwOnpvvtH3WKKnu6e7p7uYYD6njNn+lF9u+rW/dzf7/7u794WFEGR8tAtwFRgFUJMCsc2Nxap3AeA24AXRZfgjOpPIxJfvtpRogiN+C7gSSCgXnqRgLg5vHdzUxvLnQ78wHOOM+kcnBLe6UPi6zgBJFIeuht4wgMHbYVk09l9hDwYd+FI1Sw6BaaEd21K+rfOV4cGJFIe+hfg8TRwuJpPQNyUDyQKjhnA97McNptOgfvCuzb5lsRXyRUoEI57WoED4Nsk5S8jlVWdci1XHoz/sBU4ACYTT86K9AgL//b56nAWJFIemgj8LA+4FihLEs9oOXpfLOSBxkeAB/M4lTl0Ckz2LYmvDmNBIuWhO/OEA+A6kvL5bD2+PND4cJ5wAEwinvypfwt9dQgLEjmrOkA8+QnwpQK/qwHI1NufUaC7lwQqww3Rv/i38tiof21NEGDdhrrESe9iRcpDC4BvFfA9HwLPZ3l/ONCngHJtgkIP79nc6s0xdE0DLlZP95mWvaCtlWfoWndgtHq6w7TsV7Mc20tdZyHab1r2/OZG2TcgZfJWoKyIbWG3admvZIWhX9+ATCZ1dR01wFeAL6q3PwM+Bf4PsIDXTcvekaU+zgcua+Wc4kAM2CqE+MO6DXU5B3wuNS4RiURigmrjcdOy56nvHQQMSTn835UH86Jp2ZvUcYMBvSxPnG5BchpwRZ5wDAw3RD/MAt4cYDlw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"/>
<br>
</div>
</body>
</html>
"@
$NewHtmlReport | Out-File "$OutputDirectory\$TargetDomain-Share-Inventory-Summary-Report2.html"

        # ----------------------------------------------------------------------
        # Display final summary - HTML
        # ----------------------------------------------------------------------
$HTMLReport1 = @"        
        <HTML>
         <HEAD>
         </HEAD>
         <BODY>
            <H1>SMB Share Inventory Summary Report</H1>
            <strong>Domain:</strong>$TargetDomain<Br>
			
			<H3>Scan Time</H3>
			<ul>
				<li>Start Time: $StartTime</li>
				<li>End Time: $EndTime</li>
				<li>Run Time: $RunTime</li>
			</ul>
            
            <H3>Computer Summary</H3>
            
            <ul>
             <li>$ComputerCount domain computers found.</li>
             <li>$ComputerPingableCount domain computers responded to ping.</li>
             <li>$Computers445OpenCount domain computers had TCP port 445 accessible.</li>             
            </ul>
            
            <H3>Share Summary</H3>
            
            <ul>
             <li>$AllSMBSharesCount shares were found.</li>
             <li>$ExcessiveSharesCount shares across $ComputerWithExcessive systems are configured with $ExcessiveSharePrivsCount potentially excessive ACLs.</li>
             <li>$SharesWithWriteCount shares across $ComputerWithWriteCount systems can be written to.</li>
             <li>$SharesHighRiskCount shares across $ComputerwithHighRisk systems are considered high risk. (c`$,admin`$,wwwroot)</li>
             <li>$Top5ShareCountTotal of $AllAccessibleSharesCount ($DupPercent) shares are associated with the top 5 share names.<Br>
                 The 5 most common share names are:<br>
                 <ul>
"@

        $HTMLReport2 = $CommonShareNamesTop5 |
        foreach {
            $ShareCount = $_.count
            $ShareName = $_.name
            Write-Output "<li>$ShareCount $ShareName</li>"   
        }                 

        $HTMLReport3 = @" 
               </ul>
             </li>
           </ul>                                   
         </BODY>
        </HTML>
"@

        $HTMLReport = $HTMLReport1 + $HTMLReport2 + $HTMLReport3
        Write-Output " [*] Saving results to $OutputDirectory\$TargetDomain-Share-Inventory-Summary-Report.html"        
        $HTMLReport | Out-File "$OutputDirectory\$TargetDomain-Share-Inventory-Summary-Report.html"      
                
        # ----------------------------------------------------------------------
        # Generate Excessive Privilege Findings
        # ----------------------------------------------------------------------
        if($ExportFindings){           
                        
            Write-Output " [*] Generating exccessive privileges export."        

            # Define excessive priv fields           
            $ExcessivePrivID = "M:2989294"
            $ExcessivePrivName = "Excessive Privileges - Network Shares"
            $ExcessivePrivFinding = "At least one network share has been configured with excessive privileges.  Excessive privileges include shares that are configured to provide the Everyone, BUILTIN\Users, Authenticated Users, or Domain Users groups with access that is not required."
            $ExcessivePrivRecommmend = "Practice the principle of least privileges and only allow users with a defined business need to access the affected shares."
            
            # Create a finding for each instance
            $PrivExport = $ExcessiveSharePrivs |  
            Foreach {

                # Grab default fields
                $ComputerName      =  $_.ComputerName
                $IpAddress         =  $_.IpAddress 
                $ShareName         =  $_.ShareName
                $SharePath         =  $_.SharePath
                $ShareDescription  =  $_.ShareDescription
                $ShareOwner        =  $_.ShareOwner
                $ShareACcess       =  $_.ShareACcess
                $FileSystemRights  =  $_.FileSystemRights
                $AccessControlType =  $_.AccessControlType
                $IdentityReference =  $_.IdentityReference
                $IdentitySID       =  $_.IdentitySID
                $AccessControlType =  $_.AccessControlType
                $LastModifiedDate  =  $_.LastModifiedDate
                $FileCount         =  $_.FileCount
                $FileList          =  $_.FileList 

                # Create new finding object
                $object = New-Object psobject
                $object | add-member noteproperty MasterFindingSourceIdentifier $ExcessivePrivID
                $object | add-member noteproperty InstanceName            "Excessive Share ACL"
                $object | add-member noteproperty AssetName               $ComputerName       
                $object | add-member noteproperty IssueFirstFoundDate     $EndTime
                $object | add-member noteproperty VerificationCaption01   "$IdentityReference has $FileSystemRights privileges on $SharePath." 
                $ShareDetails = @"
Computer Name: $ComputerName
IP Address: $IpAddress 
Share Name: $ShareName
Share Path: $SharePath
Share Description: $ShareDescription
Share Owner $ShareOwner
Share Accses: $ShareACcess
File System Rights: $FileSystemRights
Access Control Type: $AccessControlType
Identify Reference: $IdentityReference
Identity SID: $IdentitySID
Access Control Type: $AccessControlType
Last Modification Date: $LastModifiedDate
File Count: $FileCount
File List Sample: 
$FileList 
"@                
                $object | add-member noteproperty VerificationText01      $ShareDetails
                $object | add-member noteproperty VerificationCaption02   "caption 2"
                $object | add-member noteproperty VerificationText02      "text 2"
                $object | add-member noteproperty VerificationCaption03   "caption 3"
                $object | add-member noteproperty VerificationText03      "text 3"
                $object | add-member noteproperty VerificationCaption04   "caption 4"
                $object | add-member noteproperty VerificationText04      "text 4"
                $object
            }

            # Write export file            
            $PrivExport | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Excessive-Privileges-EXPORT.csv" -Append

            # Create record containing verification summary for domain
            $object = New-Object psobject
            $object | add-member noteproperty MasterFindingSourceIdentifier $ExcessivePrivID
            $object | add-member noteproperty InstanceName            "Domain ACL Summary"
            $object | add-member noteproperty AssetName               $TargetDomain       
            $object | add-member noteproperty IssueFirstFoundDate     $EndTime            
            $object | add-member noteproperty VerificationCaption01   "$ExcessiveSharesCount shares across $ComputerWithExcessive systems are configured with $ExcessiveSharePrivsCount potentially excessive ACLs." 
            $ShareDetails = $ExcessiveSharePrivs | Select-Object SharePath -Unique -ExpandProperty SharePath | Out-String            
            $object | add-member noteproperty VerificationText01      $ShareDetails
            $object | add-member noteproperty VerificationCaption02   "$TargetDomain SMB Share Scan Summary"
            $Summary1 = @"
Target Domain: $TargetDomain

Scan Summary
Start Time: $StartTime
End Time: $EndTime
Run Time: $RunTime

Computer Summary
$ComputerCount domain computers found
$ComputerPingableCount domain computers responded to ping
$Computers445OpenCount domain computers had TCP port 445 accessible         

Share Summary
$AllSMBSharesCount shares were found.
$ExcessiveSharesCount shares across $ComputerWithExcessive systems are configured with $ExcessiveSharePrivsCount potentially excessive ACLs.
$SharesWithWriteCount shares across $ComputerWithWriteCount systems can be written to.</li>
$SharesHighRiskCount shares across $ComputerwithHighRisk systems are considered high risk.
$Top5ShareCountTotal of $AllAccessibleSharesCount ($DupPercent) shares are associated with the top 5 share names.

The 5 most common share names are:

"@

            $Summary2 = $CommonShareNamesTop5 |
            foreach {
                $ShareCount = $_.count
                $ShareName = $_.name
                Write-Output "- $ShareCount $ShareName"   
            } | Out-String                

            $SummaryFinal = $Summary1 + $Summary2

            $object | add-member noteproperty VerificationText02      "$SummaryFinal"
            $object | add-member noteproperty VerificationCaption03   "caption 3"
            $object | add-member noteproperty VerificationText03      "text 3"
            $object | add-member noteproperty VerificationCaption04   "caption 4"
            $object | add-member noteproperty VerificationText04      "text 4"
            
            # Write record to file
            $object | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Excessive-Privileges-EXPORT.csv" -Append
        }

        # ----------------------------------------------------------------------
        # Generate Excessive Privilege Findings - High Risk
        # ----------------------------------------------------------------------
        if($ExportFindings){

            Write-Output " [*] Generating HIGH RISK exccessive privileges export." 

            # Define excessive priv fields 
            $ExcessivehighRiskID = "MAN:M:e581ab69-a0fc-4cb1-a7ff-87256c1a9e91"
            $ExcessivehighRiskName = "Excessive Privileges - Network Shares - High Risk"
            $ExcessiveHighRiskFinding = "At least one network share has been configured with high risk excessive privileges.  High risk excessive privileges  provide the Everyone, BUILTIN\Users, Authenticated Users, or Domain Users groups with read/write access to system shares, web roots, or directories containing potentially sensitive data."
            $ExcessiveHighRiskRecommmend = "Practice the principle of least privileges and only allow users with a defined business need to access the affected shares."
                

            # Create a finding for each instance
            $PrivHighExport = $SharesHighRisk | 
            Foreach {

                # Grab default fields
                $ComputerName      =  $_.ComputerName
                $IpAddress         =  $_.IpAddress 
                $ShareName         =  $_.ShareName
                $SharePath         =  $_.SharePath
                $ShareDescription  =  $_.ShareDescription
                $ShareOwner        =  $_.ShareOwner
                $ShareACcess       =  $_.ShareACcess
                $FileSystemRights  =  $_.FileSystemRights
                $AccessControlType =  $_.AccessControlType
                $IdentityReference =  $_.IdentityReference
                $IdentitySID       =  $_.IdentitySID
                $AccessControlType =  $_.AccessControlType
                $LastModifiedDate  =  $_.LastModifiedDate
                $FileCount         =  $_.FileCount
                $FileList          =  $_.FileList 

                # Create new finding object
                $object = New-Object psobject
                $object | add-member noteproperty MasterFindingSourceIdentifier $ExcessivehighRiskID
                $object | add-member noteproperty InstanceName            "Excessive Share ACL"
                $object | add-member noteproperty AssetName               $ComputerName       
                $object | add-member noteproperty IssueFirstFoundDate     $EndTime
                $object | add-member noteproperty VerificationCaption01   "$IdentityReference has $FileSystemRights privileges on $SharePath." 
                $ShareDetails = @"
Computer Name: $ComputerName
IP Address: $IpAddress 
Share Name: $ShareName
Share Path: $SharePath
Share Description: $ShareDescription
Share Owner $ShareOwner
Share Accses: $ShareACcess
File System Rights: $FileSystemRights
Access Control Type: $AccessControlType
Identify Reference: $IdentityReference
Identity SID: $IdentitySID
Access Control Type: $AccessControlType
Last Modification Date: $LastModifiedDate
File Count: $FileCount
File List Sample: 
$FileList 
"@                
                $object | add-member noteproperty VerificationText01      $ShareDetails
                $object | add-member noteproperty VerificationCaption02   "caption 2"
                $object | add-member noteproperty VerificationText02      "text 2"
                $object | add-member noteproperty VerificationCaption03   "caption 3"
                $object | add-member noteproperty VerificationText03      "text 3"
                $object | add-member noteproperty VerificationCaption04   "caption 4"
                $object | add-member noteproperty VerificationText04      "text 4"
                $object
            }

            # Write export file            
            $PrivHighExport | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Excessive-Privileges-EXPORT.csv" -Append


            # Create record containing verification summary for domain
            $object = New-Object psobject
            $object | add-member noteproperty MasterFindingSourceIdentifier $ExcessivehighRiskID
            $object | add-member noteproperty InstanceName            "Domain ACL Summary"
            $object | add-member noteproperty AssetName               $TargetDomain       
            $object | add-member noteproperty IssueFirstFoundDate     $EndTime            
            $object | add-member noteproperty VerificationCaption01   "$SharesHighRiskCount shares across $ComputerwithHighRisk systems are considered high risk." 
            $ShareDetails = $SharesHighRisk | Select-Object SharePath -Unique -ExpandProperty SharePath | Out-String            
            $object | add-member noteproperty VerificationText01      $ShareDetails
            $object | add-member noteproperty VerificationCaption02   "$TargetDomain SMB Share Scan Summary"
            $Summary1 = @"
Target Domain: $TargetDomain

Scan Summary
Start Time: $StartTime
End Time: $EndTime
Run Time: $RunTime

Computer Summary
$ComputerCount domain computers found
$ComputerPingableCount domain computers responded to ping
$Computers445OpenCount domain computers had TCP port 445 accessible         

Share Summary
$AllSMBSharesCount shares were found.
$ExcessiveSharesCount shares across $ComputerWithExcessive systems are configured with $ExcessiveSharePrivsCount potentially excessive ACLs.
$SharesWithWriteCount shares across $ComputerWithWriteCount systems can be written to.</li>
$SharesHighRiskCount shares across $ComputerwithHighRisk systems are considered high risk.
$Top5ShareCountTotal of $AllAccessibleSharesCount ($DupPercent) shares are associated with the top 5 share names.

The 5 most common share names are:

"@

            $Summary2 = $CommonShareNamesTop5 |
            foreach {
                $ShareCount = $_.count
                $ShareName = $_.name
                Write-Output "- $ShareCount $ShareName"   
            } | Out-String                

            $SummaryFinal = $Summary1 + $Summary2

            $object | add-member noteproperty VerificationText02      "$SummaryFinal"
            $object | add-member noteproperty VerificationCaption03   "caption 3"
            $object | add-member noteproperty VerificationText03      "text 3"
            $object | add-member noteproperty VerificationCaption04   "caption 4"
            $object | add-member noteproperty VerificationText04      "text 4"
            
            # Write record to file
            $object | Export-Csv -NoTypeInformation "$OutputDirectory\$TargetDomain-Excessive-Privileges-EXPORT.csv" -Append
        }       
        
        Write-Output " [*] Results exported to $OutputDirectory\$TargetDomain-Excessive-Privileges-EXPORT.csv"               
    }
}


# //////////////////////////////////////////////////////////////////////////
# Functions used by Get-SmbShareInventory
# //////////////////////////////////////////////////////////////////////////

# -------------------------------------------
# Function: Get-PercentDisplay
# -------------------------------------------
function Get-PercentDisplay
{
    param (
        $TargetCount,
        $FullCount
    )

    $Percent = [math]::Round($TargetCount/$FullCount,4)
    $PercentString = $Percent.tostring("P") -replace(" ","")
    $PercentBarVal = ($Percent *2).tostring("P") -replace(" %","px")

    # Return object with all counts
    $TheCounts = new-object psobject            
    $TheCounts | add-member  Noteproperty PercentString         $PercentString
    $TheCounts | add-member  Noteproperty PercentBarVal         $PercentBarVal    
    $TheCounts
}

# -------------------------------------------
# Function: Get-GroupOwnerBar
# -------------------------------------------
function Get-GroupOwnerBar
{
    param (
        $DataTable,
        $Name,
        $AllComputerCount,
        $AllShareCount,
        $AllAclCount
    )

    # Get acl counts
    $UserAcls = $DataTable | Where ShareOwner -like "$Name" | Select-Object ComputerName,ShareOwner,SharePath,FileSystemRights
    $UserAclsCount = $UserAcls | measure | select count -ExpandProperty count
    $UserAclsPercent = [math]::Round($UserAclsCount/$AllAclCount,4)
    $UserAclsPercentString = $UserAclsPercent.tostring("P") -replace(" ","")
    $UserAclsPercentBarVal = ($UserAclsPercent *2).tostring("P") -replace(" %","px")
    $UserAclsPercentBarCode = "<span class=`"dashboardsub2`">$UserAclsPercentString ($UserAclsCount of $AllAclCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserAclsPercentString;`"></div></div>"

    # Get share counts
    $UserShare = $UserAcls | Select-Object SharePath -Unique
    $UserShareCount = $UserShare | measure | select count -ExpandProperty count
    $UserSharePercent = [math]::Round($UserShareCount/$AllShareCount,4)
    $UserSharePercentString = $UserSharePercent.tostring("P") -replace(" ","")
    $UserSharePercentBarVal = ($UserSharePercent *2).tostring("P") -replace(" %","px")
    $UserSharePercentBarCode = "<span class=`"dashboardsub2`">$UserSharePercentString ($UserShareCount of $AllShareCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserSharePercentString;`"></div></div>"

    # Get computer counts
    $UserComputer = $UserAcls | Select-Object ComputerName -Unique
    $UserComputerCount = $UserComputer | measure | select count -ExpandProperty count   
    $UserComputerPercent = [math]::Round($UserComputerCount/$AllComputerCount,4)
    $UserComputerPercentString = $UserComputerPercent.tostring("P") -replace(" ","")
    $UserComputerPercentBarVal = ($UserComputerPercent *2).tostring("P") -replace(" %","px")
    $UserComputerPercentBarCode = "<span class=`"dashboardsub2`">$UserComputerPercentString ($UserComputerCount of $AllComputerCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserComputerPercentString;`"></div></div>"

    # Return object with all counts
    $TheCounts = new-object psobject            
    $TheCounts | add-member  Noteproperty ComputerBar   $UserComputerPercentBarCode
    $TheCounts | add-member  Noteproperty ShareBar      $UserSharePercentBarCode    
    $TheCounts | add-member  Noteproperty AclBar        $UserAclsPercentBarCode
    $TheCounts
}

# -------------------------------------------
# Function: Get-GroupNameBar
# -------------------------------------------
function Get-GroupNameBar
{
    param (
        $DataTable,
        $Name,
        $AllComputerCount,
        $AllShareCount,
        $AllAclCount
    )

    # Get acl counts
    $UserAcls = $DataTable | Where ShareName -like "$Name" | Select-Object ComputerName, ShareName, SharePath, FileSystemRights
    $UserAclsCount = $UserAcls | measure | select count -ExpandProperty count
    $UserAclsPercent = [math]::Round($UserAclsCount/$AllAclCount,4)
    $UserAclsPercentString = $UserAclsPercent.tostring("P") -replace(" ","")
    $UserAclsPercentBarVal = ($UserAclsPercent *2).tostring("P") -replace(" %","px")
    $UserAclsPercentBarCode = "<span class=`"dashboardsub2`">$UserAclsPercentString ($UserAclsCount of $AllAclCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserAclsPercentString;`"></div></div>"

    # Get share counts
    $UserShare = $UserAcls | Select-Object SharePath -Unique
    $UserShareCount = $UserShare | measure | select count -ExpandProperty count
    $UserSharePercent = [math]::Round($UserShareCount/$AllShareCount,4)
    $UserSharePercentString = $UserSharePercent.tostring("P") -replace(" ","")
    $UserSharePercentBarVal = ($UserSharePercent *2).tostring("P") -replace(" %","px")
    $UserSharePercentBarCode = "<span class=`"dashboardsub2`">$UserSharePercentString ($UserShareCount of $AllShareCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserSharePercentString;`"></div></div>"

    # Get computer counts
    $UserComputer = $UserAcls | Select-Object ComputerName -Unique
    $UserComputerCount = $UserComputer | measure | select count -ExpandProperty count   
    $UserComputerPercent = [math]::Round($UserComputerCount/$AllComputerCount,4)
    $UserComputerPercentString = $UserComputerPercent.tostring("P") -replace(" ","")
    $UserComputerPercentBarVal = ($UserComputerPercent *2).tostring("P") -replace(" %","px")
    $UserComputerPercentBarCode = "<span class=`"dashboardsub2`">$UserComputerPercentString ($UserComputerCount of $AllComputerCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserComputerPercentString;`"></div></div>"

    # Return object with all counts
    $TheCounts = new-object psobject            
    $TheCounts | add-member  Noteproperty ComputerBar   $UserComputerPercentBarCode
    $TheCounts | add-member  Noteproperty ShareBar      $UserSharePercentBarCode    
    $TheCounts | add-member  Noteproperty AclBar        $UserAclsPercentBarCode
    $TheCounts
}

# -------------------------------------------
# Function: Get-GroupFileBar
# -------------------------------------------
function Get-GroupFileBar
{
    param (
        $DataTable,
        $Name,
        $AllComputerCount,
        $AllShareCount,
        $AllAclCount
    )

    # Get acl counts
    $UserAcls = $DataTable | Where FileListGroup -like "$Name" | Select-Object ComputerName, ShareName, SharePath, FileSystemRights, FileCount, FileList
    $FolderInfo = $UserAcls | select FileCount, FileList -First 1
    $FileCount = $FolderInfo.FileCount 
    $FileList = $FolderInfo.FileList 
    $UserAclsCount = $UserAcls | measure | select count -ExpandProperty count
    $UserAclsPercent = [math]::Round($UserAclsCount/$AllAclCount,4)
    $UserAclsPercentString = $UserAclsPercent.tostring("P") -replace(" ","")
    $UserAclsPercentBarVal = ($UserAclsPercent *2).tostring("P") -replace(" %","px")
    $UserAclsPercentBarCode = "<span class=`"dashboardsub2`">$UserAclsPercentString ($UserAclsCount of $AllAclCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserAclsPercentString;`"></div></div>"

    # Get share counts
    $UserShare = $UserAcls | Select-Object SharePath -Unique
    $UserShareCount = $UserShare | measure | select count -ExpandProperty count
    $UserSharePercent = [math]::Round($UserShareCount/$AllShareCount,4)
    $UserSharePercentString = $UserSharePercent.tostring("P") -replace(" ","")
    $UserSharePercentBarVal = ($UserSharePercent *2).tostring("P") -replace(" %","px")
    $UserSharePercentBarCode = "<span class=`"dashboardsub2`">$UserSharePercentString ($UserShareCount of $AllShareCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserSharePercentString;`"></div></div>"

    # Get computer counts
    $UserComputer = $UserAcls | Select-Object ComputerName -Unique
    $UserComputerCount = $UserComputer | measure | select count -ExpandProperty count   
    $UserComputerPercent = [math]::Round($UserComputerCount/$AllComputerCount,4)
    $UserComputerPercentString = $UserComputerPercent.tostring("P") -replace(" ","")
    $UserComputerPercentBarVal = ($UserComputerPercent *2).tostring("P") -replace(" %","px")
    $UserComputerPercentBarCode = "<span class=`"dashboardsub2`">$UserComputerPercentString ($UserComputerCount of $AllComputerCount)</span><br><div class=`"divbarDomain`"><div class=`"divbarDomainInside`" style=`"width: $UserComputerPercentString;`"></div></div>"

    # Return object with all counts
    $TheCounts = new-object psobject            
    $TheCounts | add-member  Noteproperty ComputerBar   $UserComputerPercentBarCode
    $TheCounts | add-member  Noteproperty ShareBar      $UserSharePercentBarCode    
    $TheCounts | add-member  Noteproperty AclBar        $UserAclsPercentBarCode
    $TheCounts | add-member  Noteproperty FileCount     $FileCount
    $TheCounts | add-member  Noteproperty FileList      $FileList
    $TheCounts | add-member  Noteproperty ShareCount    $UserShareCount
    $TheCounts
}

# -------------------------------------------
# Function: Get-UserAceCounts
# -------------------------------------------
function Get-UserAceCounts
{
    param (
        $DataTable,
        $UserName
    )

    # Get acl counts
    $UserAcls = $DataTable | Where IdentityReference -like "$UserName" | Select-Object ComputerName, ShareName, SharePath, FileSystemRights
    $UserAclsCount = $UserAcls | measure | select count -ExpandProperty count

    # Get share counts
    $UserShare = $UserAcls | Select-Object SharePath -Unique
    $UserShareCount = $UserShare  | measure | select count -ExpandProperty count

    # Get computer counts
    $UserComputer = $UserAcls | Select-Object ComputerName -Unique
    $UserComputerCount = $UserComputer | measure | select count -ExpandProperty count

    # Get read counts 
    $UserReadAcl = $UserAcls | 
    Foreach {

        if(($_.FileSystemRights -like "*read*"))
        {
            $_ 
        }
    }
    $UserReadAclCount = $UserReadAcl | measure | select count -ExpandProperty count

    # Get write counts
    $UserWriteAcl = $UserAcls | 
    Foreach {

        if(($_.FileSystemRights -like "*GenericAll*") -or ($_.FileSystemRights -like "*Write*"))
        {
            $_ 
        }
    }
    $UserWriteAclCount = $UserWriteAcl | measure | select count -ExpandProperty count

    # Get high risk counts
    $UserHighRiskAcl = $UserAcls | 
    Foreach {

        if(($_.ShareName -like 'c$') -or ($_.ShareName -like 'admin$') -or ($_.ShareName -like "*wwwroot*") -or ($_.ShareName -like "*inetpub*") -or ($_.ShareName -like 'c') -or ($_.ShareName -like 'c_share'))
        {
            $_ 
        }
    }
    $UserHighRiskAclCount = $UserHighRiskAcl | measure | select count -ExpandProperty count

    # Return object with all counts
    $TheCounts = new-object psobject            
    $TheCounts | add-member  Noteproperty UserAclsCount          $UserAclsCount
    $TheCounts | add-member  Noteproperty UserShareCount         $UserShareCount
    $TheCounts | add-member  Noteproperty UserComputerCount      $UserComputerCount
    $TheCounts | add-member  Noteproperty UserReadAclCount       $UserReadAclCount
    $TheCounts | add-member  Noteproperty UserWriteAclCount      $UserWriteAclCount
    $TheCounts | add-member  Noteproperty UserHighRiskAclCount   $UserHighRiskAclCount
    $TheCounts
}

# -------------------------------------------
# Function: Convert-DataTableToHtmlTable
# -------------------------------------------
function Convert-DataTableToHtmlTable
{
    <#
            .SYNOPSIS
            This function can be used to convert a data table or ps object into a html table.
            .PARAMETER $DataTable
            The datatable to input.
            .PARAMETER $Outfile
            The output file path.
            .PARAMETER $Title
            Title of the page.
            .PARAMETER $Description
            Description of the page.
            .EXAMPLE
            $object = New-Object psobject
            $Object | Add-Member Noteproperty Name "my name 1"
            $Object | Add-Member Noteproperty Description "my description 1"
            Convert-DataTableToHtmlTable -Verbose -DataTable $object -Outfile ".\MyPsDataTable.html" -Title "MyPage" -Description "My description" -DontExport
            Convert-DataTableToHtmlTable -Verbose -DataTable $object -Outfile ".\MyPsDataTable.html" -Title "MyPage" -Description "My description"            
            .\MyPsDataTable.html
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
    #>
    param (
        [Parameter(Mandatory = $true,
        HelpMessage = 'The datatable to input.')]
        $DataTable,
        [Parameter(Mandatory = $false,
        HelpMessage = 'The output file path.')]
        [string]$Outfile = ".\MyPsDataTable.html",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Title of page.')]
        [string]$Title = "HTML Table",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Description of page.')]
        [string]$Description = "HTML Table",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Disable file save.')]
        [switch]$DontExport
    )

    # Setup HTML begin
    Write-Verbose "[+] Creating html top." 
    $HTMLSTART = @"
    <html>
        <head>
          <title>$Title</title>
          <style> 	
  
	        {box-sizing:border-box}
	        body,html{
		        font-family:"Open Sans", 
		        sans-serif;font-weight:400;
		        min-height:100%;;color:#3d3935;
		        margin:1px;line-height:1.5;
		        overflow-x:hidden
	        }
		
	        table{
		        width:100%;
		        max-width:100%;
		        margin-bottom:1rem;
		        border-collapse:collapse
	        }
	
	        table thead th{
		        vertical-align:bottom;
		        border-bottom:2px solid #eceeef
	        }
	
	        table tbody tr:nth-of-type(odd){
		        background-color:#f9f9f9
	        }
	
	        table tbody tr:hover{
		        background-color:#f5f5f5
	        }
	
	        table td,table th{
		        padding:.75rem;
		        line-height:1.5;
		        text-align:left;
		        font-size:1rem;
		        vertical-align:top;
		        border-top:1px solid #eceeef
	        }

	
	        h1,h2,h3,h4,h5,h6{
		        padding-left: 10px;
		        font-family:inherit;
		        font-weight:500;
		        line-height:1.1;
		        color:inherit
	        }
	
	        code{
		        padding:.2rem .4rem;
		        font-size:1rem;
		        color:#bd4147;
		        background-color:#f7f7f9;
		        border-radius:.25rem
	        }
	
	        p{
		        margin-top:0;
		        margin-bottom:1rem
	        }
	
	        a,a:visited{
		        text-decoration:none;
		        font-size: 14;
		        color: gray;
		        font-weight: bold;
	        }
	
	        a:hover{
		        color:#9B3722;
		        text-decoration:underline
	        }
		
	        .link:hover{
		        text-decoration:underline
	        }
	
	        li{
		        list-style-type:none
	        }	

            .pageDescription {
                margin: 10px;
            }
  
	        .divbarDomain{
		        background:#d9d7d7;
		        width:200px;
		        border: 1px solid #999999;
		        height: 25px;
		        text-align:center;
	        }
  
	        .divbarDomainInside{
		        background:#9B3722;
		        width:100px;
		        text-align:center;
		        height: 25px;
		        vertical-align:middle;
            }
            .pageDescription {
                padding-left: 0px;
            }				
          </style>
        </head>
        <body>
        <p class="pageDescription"><a href="javascript:history.back()">Back to Report</a></p>
        <p class="pageDescription"><h3>$Title</h3></p>
        <p class="pageDescription">$Description</p>
            <table class="table table-striped table-hover">
"@
    
    # Get list of columns
    Write-Verbose "[+] Parsing data table columns."
    $MyCsvColumns = $DataTable | Get-Member | Where-Object MemberType -like "NoteProperty" | Select-Object Name -ExpandProperty Name

    # Print columns creation
    Write-Verbose "[+] Creating html table columns."   
    $HTMLTableHeadStart= "<thead><tr>" 
    $MyCsvColumns |
    ForEach-Object {

        # Add column
        $HTMLTableColumn = "<th>$_</th>$HTMLTableColumn"    
    }
    $HTMLTableColumn = "$HTMLTableHeadStart$HTMLTableColumn</tr></thead>" 

     # Create table rows
    Write-Verbose "[+] Creating html table rows."     
    $HTMLTableRow = $DataTable |
    ForEach-Object {
    
        # Create a value contain row data
        $CurrentRow = $_
        $PrintRow = ""
        $MyCsvColumns | 
        ForEach-Object{
            $GetValue = $CurrentRow | Select-Object $_ -ExpandProperty $_ 
            if($PrintRow -eq ""){
                $PrintRow = "<td>$GetValue</td>"               
            }else{         
                $PrintRow = "<td>$GetValue</td>$PrintRow"
            }
        }
        
        # Return row
        $HTMLTableHeadstart = "<tr>" 
        $HTMLTableHeadend = "</tr>" 
        "$HTMLTableHeadStart$PrintRow$HTMLTableHeadend"
    }

    # Setup HTML end
    Write-Verbose "[+] Creating html bottom." 
    $HTMLEND = @"
  </tbody>
</table>
</body>
</html>
"@

    # Return it
    "$HTMLSTART $HTMLTableColumn $HTMLTableRow $HTMLEND" 

    # Write file
    if(-not $DontExport){
        "$HTMLSTART $HTMLTableColumn $HTMLTableRow $HTMLEND"  | Out-File $Outfile
    }
}

# -------------------------------------------
# Function: Get-FolderGroupMd5
# -------------------------------------------
function Get-FolderGroupMd5{
    
    param (
        [string]$FolderList
    )

    <#
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.write($FolderList)
    $writer.Flush()
    $stringAsStream.Position = 0
    Get-FileHash -InputStream $stringAsStream -Algorithm MD5 | Select-Object Hash
    #>

    $MyMd5Provider = [System.Security.Cryptography.MD5CryptoServiceProvider]::Create()
    $enc = [system.Text.Encoding]::UTF8
    $FolderListBytes = $enc.GetBytes($FolderList) 
    $MyMd5HashBytes = $MyMd5Provider.ComputeHash($FolderListBytes)
    $MysStringBuilder = new-object System.Text.StringBuilder
    $MyMd5HashBytes|
    foreach {
       $MyMd5HashByte =  $_.ToString("x2").ToLower()
       $MyMd5Hash = "$MyMd5Hash$MyMd5HashByte"
    }
    $MyMd5Hash
}

# -------------------------------------------
# Function: Get-LdapQuery
# -------------------------------------------
# Author: Scott Sutherland
function Get-LdapQuery
{    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain user to authenticate with domain\user.')]
        [string]$Username,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain password to authenticate with domain\user.')]
        [string]$Password,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Credentials to use when connecting to a Domain Controller.')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Domain controller for Domain and Site that you want to query against.')]
        [string]$DomainController,

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP Filter.')]
        [string]$LdapFilter = '',

        [Parameter(Mandatory = $false,
        HelpMessage = 'LDAP path.')]
        [string]$LdapPath,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Maximum number of Objects to pull from AD, limit is 1,000 .')]
        [int]$Limit = 1000,

        [Parameter(Mandatory = $false,
        HelpMessage = 'scope of a search as either a base, one-level, or subtree search, default is subtree.')]
        [ValidateSet('Subtree','OneLevel','Base')]
        [string]$SearchScope = 'Subtree'
    )
    Begin
    {
        # Create PS Credential object
        if($Username -and $Password)
        {
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)
        }

        # Create Create the connection to LDAP
        if ($DomainController)
        {
           
            # Verify credentials were provided
            if(-not $Username){
                Write-Output "A username and password must be provided when setting a specific domain controller."
                Break
            }

            # Test credentials and grab domain
            try {
                $objDomain = (New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password).distinguishedname
            }catch{
                Write-Output "Authentication failed."
            }

            # add ldap path
            if($LdapPath)
            {
                $LdapPath = '/'+$LdapPath+','+$objDomain
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController$LdapPath", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }
            else
            {
                $objDomainPath = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$DomainController", $Credential.UserName, $Credential.GetNetworkCredential().Password
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }
        else
        {
            $objDomain = ([ADSI]'').distinguishedName

            if($LdapPath)
            {
                $LdapPath = $LdapPath+','+$objDomain
                $objDomainPath  = [ADSI]"LDAP://$LdapPath"
            }
            else
            {
                $objDomainPath  = [ADSI]''
            }

            $objSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $objDomainPath
        }

        # Setup LDAP filter
        $objSearcher.PageSize = $Limit
        $objSearcher.Filter = $LdapFilter
        $objSearcher.SearchScope = 'Subtree'
    }

    Process
    {    
        try
        {
            # Return object
            $objSearcher.FindAll() | ForEach-Object -Process {
                $_
            }
        }
        catch
        {
            "Error was $_"
            $line = $_.InvocationInfo.ScriptLineNumber
            "Error was in Line $line"
        }
    }

    End
    {
    }
}


# -------------------------------------------
# Function: Invoke-Parallel
# -------------------------------------------
# Author: RamblingCookieMonster
# Source: https://github.com/RamblingCookieMonster/Invoke-Parallel
# Notes: Added "ImportSessionFunctions" to import custom functions from the current session into the runspace pool.
function Invoke-Parallel
{
    <#
            .SYNOPSIS
            Function to control parallel processing using runspaces

            .DESCRIPTION
            Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

            .PARAMETER ScriptFile
            File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

            .PARAMETER ScriptBlock
            Scriptblock to run against all computers.

            You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
            Refer to the input object as $_.
            Refer to the parameter parameter as $parameter

            .PARAMETER InputObject
            Run script against these specified objects.

            .PARAMETER Parameter
            This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

            .PARAMETER ImportVariables
            If specified, get user session variables and add them to the initial session state

            .PARAMETER ImportModules
            If specified, get loaded modules and pssnapins, add them to the initial session state

            .PARAMETER Throttle
            Maximum number of threads to run at a single time.

            .PARAMETER SleepTimer
            Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

            .PARAMETER RunspaceTimeout
            Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

            WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
            http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

            .PARAMETER NoCloseOnTimeout
            Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

            .PARAMETER MaxQueue
            Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

            If this is equal or less than throttle, there will be a performance impact

            The default value is $throttle times 3, if $runspaceTimeout is not specified
            The default value is $throttle, if $runspaceTimeout is specified

            .PARAMETER LogFile
            Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

            .PARAMETER Quiet
            Disable progress bar.

            .EXAMPLE
            Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=1;
            Kodak=$(
            if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users

            \desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
            )
            }
            }
            else{
            $object = [pscustomobject] @{
            Computer=$computer;
            Available=0;
            Kodak="NA"
            }
            }

            $object

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

            .EXAMPLE
            Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

            .EXAMPLE
            $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
            }

            $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
            set-content $parameter.logfile
            }

            This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

            Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

            Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

            .EXAMPLE
            $test = 5
            1..2 | Invoke-Parallel {$_ * $Using:test}

            Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

            .FUNCTIONALITY
            PowerShell Language

            .NOTES
            Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

            Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

            Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

            .LINK
            https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        If (-not($SuppressVerbose)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}

# Source: https://stackoverflow.com/questions/35116636/bit-shifting-in-powershell-2-0
function Convert-BitShift {
    param (
        [Parameter(Position = 0, Mandatory = $True)]
        [int] $Number,

        [Parameter(ParameterSetName = 'Left', Mandatory = $False)]
        [int] $Left,

        [Parameter(ParameterSetName = 'Right', Mandatory = $False)]
        [int] $Right
    ) 

    $shift = 0
    if ($PSCmdlet.ParameterSetName -eq 'Left')
    { 
        $shift = $Left
    }
    else
    {
        $shift = -$Right
    }

    return [math]::Floor($Number * [math]::Pow(2,$shift))
}

function New-InMemoryModule
{

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            ForEach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $Null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        ForEach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    ForEach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $Null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}

function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

function struct
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    ForEach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    ForEach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}

filter Get-IniContent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [ValidateScript({ Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    ForEach($TargetPath in $Path) {
        $IniObject = @{}
        Switch -Regex -File $TargetPath {
            "^\[(.+)\]" # Section
            {
                $Section = $matches[1].Trim()
                $IniObject[$Section] = @{}
                $CommentCount = 0
            }
            "^(;.*)$" # Comment
            {
                $Value = $matches[1].Trim()
                $CommentCount = $CommentCount + 1
                $Name = 'Comment' + $CommentCount
                $IniObject[$Section][$Name] = $Value
            } 
            "(.+?)\s*=(.*)" # Key
            {
                $Name, $Value = $matches[1..2]
                $Name = $Name.Trim()
                $Values = $Value.split(',') | ForEach-Object {$_.Trim()}
                if($Values -isnot [System.Array]) {$Values = @($Values)}
                $IniObject[$Section][$Name] = $Values
            }
        }
        $IniObject
    }
}

filter Export-PowerViewCSV {

    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,

        [Parameter(Mandatory=$True, Position=0)]
        [String]
        [ValidateNotNullOrEmpty()]
        $OutFile
    )

    $ObjectCSV = $InputObject | ConvertTo-Csv -NoTypeInformation

    # mutex so threaded code doesn't stomp on the output file
    $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex';
    $Null = $Mutex.WaitOne()

    if (Test-Path -Path $OutFile) {
        # hack to skip the first line of output if the file already exists
        $ObjectCSV | ForEach-Object { $Start=$True }{ if ($Start) {$Start=$False} else {$_} } | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
    }
    else {
        $ObjectCSV | Out-File -Encoding 'ASCII' -Append -FilePath $OutFile
    }

    $Mutex.ReleaseMutex()
}

filter Get-IPAddress {

    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = $Env:ComputerName
    )

    try {
        # extract the computer name from whatever object was passed on the pipeline
        $Computer = $ComputerName | Get-NameField

        # get the IP resolution of this specified hostname
        @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
            if ($_.AddressFamily -eq 'InterNetwork') {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ComputerName' $Computer
                $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                $Out
            }
        }
    }
    catch {
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
}

filter Convert-NameToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $ObjectName,

        [String]
        $Domain
    )

    $ObjectName = $ObjectName -Replace "/","\"
    
    if($ObjectName.Contains("\")) {
        # if we get a DOMAIN\user format, auto convert it
        $Domain = $ObjectName.Split("\")[0]
        $ObjectName = $ObjectName.Split("\")[1]
    }
    elseif(-not $Domain) {
        $Domain = (Get-ThisThingDomain).Name
    }

    try {
        $Obj = (New-Object System.Security.Principal.NTAccount($Domain, $ObjectName))
        $SID = $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ObjectName' $ObjectName
        $Out | Add-Member Noteproperty 'SID' $SID
        $Out
    }
    catch {
        Write-Verbose "Invalid object/name: $Domain\$ObjectName"
        $Null
    }
}

filter Convert-SidToName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [ValidatePattern('^S-1-.*')]
        $SID
    )

    try {
        $SID2 = $SID.trim('*')

        # try to resolve any built-in SIDs first
        #   from https://support.microsoft.com/en-us/kb/243330
        Switch ($SID2) {
            'S-1-0'         { 'Null Authority' }
            'S-1-0-0'       { 'Nobody' }
            'S-1-1'         { 'World Authority' }
            'S-1-1-0'       { 'Everyone' }
            'S-1-2'         { 'Local Authority' }
            'S-1-2-0'       { 'Local' }
            'S-1-2-1'       { 'Console Logon ' }
            'S-1-3'         { 'Creator Authority' }
            'S-1-3-0'       { 'Creator Owner' }
            'S-1-3-1'       { 'Creator Group' }
            'S-1-3-2'       { 'Creator Owner Server' }
            'S-1-3-3'       { 'Creator Group Server' }
            'S-1-3-4'       { 'Owner Rights' }
            'S-1-4'         { 'Non-unique Authority' }
            'S-1-5'         { 'NT Authority' }
            'S-1-5-1'       { 'Dialup' }
            'S-1-5-2'       { 'Network' }
            'S-1-5-3'       { 'Batch' }
            'S-1-5-4'       { 'Interactive' }
            'S-1-5-6'       { 'Service' }
            'S-1-5-7'       { 'Anonymous' }
            'S-1-5-8'       { 'Proxy' }
            'S-1-5-9'       { 'Enterprise Domain Controllers' }
            'S-1-5-10'      { 'Principal Self' }
            'S-1-5-11'      { 'Authenticated Users' }
            'S-1-5-12'      { 'Restricted Code' }
            'S-1-5-13'      { 'Terminal Server Users' }
            'S-1-5-14'      { 'Remote Interactive Logon' }
            'S-1-5-15'      { 'This Organization ' }
            'S-1-5-17'      { 'This Organization ' }
            'S-1-5-18'      { 'Local System' }
            'S-1-5-19'      { 'NT Authority' }
            'S-1-5-20'      { 'NT Authority' }
            'S-1-5-80-0'    { 'All Services ' }
            'S-1-5-32-544'  { 'BUILTIN\Administrators' }
            'S-1-5-32-545'  { 'BUILTIN\Users' }
            'S-1-5-32-546'  { 'BUILTIN\Guests' }
            'S-1-5-32-547'  { 'BUILTIN\Power Users' }
            'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
            'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
            'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
            'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
            'S-1-5-32-552'  { 'BUILTIN\Replicators' }
            'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
            'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
            'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
            'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
            'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
            'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
            'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
            'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
            'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
            'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
            'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
            'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
            'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
            'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
            'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
            'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
            'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
            'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
            Default { 
                $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                $Obj.Translate( [System.Security.Principal.NTAccount]).Value
            }
        }
    }
    catch {
        Write-Verbose "Invalid SID: $SID"
        $SID
    }
}

filter Convert-ADName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $ObjectName,

        [String]
        [ValidateSet("NT4","Simple","Canonical")]
        $InputType,

        [String]
        [ValidateSet("NT4","Simple","Canonical")]
        $OutputType
    )

    $NameTypes = @{
        'Canonical' = 2
        'NT4'       = 3
        'Simple'    = 5
    }

    if(-not $PSBoundParameters['InputType']) {
        if( ($ObjectName.split('/')).Count -eq 2 ) {
            $ObjectName = $ObjectName.replace('/', '\')
        }

        if($ObjectName -match "^[A-Za-z]+\\[A-Za-z ]+") {
            $InputType = 'NT4'
        }
        elseif($ObjectName -match "^[A-Za-z ]+@[A-Za-z\.]+") {
            $InputType = 'Simple'
        }
        elseif($ObjectName -match "^[A-Za-z\.]+/[A-Za-z]+/[A-Za-z/ ]+") {
            $InputType = 'Canonical'
        }
        else {
            #Write-Warning "Can not identify InType for $ObjectName"
            return $ObjectName
        }
    }
    elseif($InputType -eq 'NT4') {
        $ObjectName = $ObjectName.replace('/', '\')
    }

    if(-not $PSBoundParameters['OutputType']) {
        $OutputType = Switch($InputType) {
            'NT4' {'Canonical'}
            'Simple' {'NT4'}
            'Canonical' {'NT4'}
        }
    }

    # try to extract the domain from the given format
    $Domain = Switch($InputType) {
        'NT4' { $ObjectName.split("\")[0] }
        'Simple' { $ObjectName.split("@")[1] }
        'Canonical' { $ObjectName.split("/")[0] }
    }

    # Accessor functions to simplify calls to NameTranslate
    function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
        $Output = $Object.GetType().InvokeMember($Method, "InvokeMethod", $Null, $Object, $Parameters)
        if ( $Output ) { $Output }
    }
    function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
        [Void] $Object.GetType().InvokeMember($Property, "SetProperty", $Null, $Object, $Parameters)
    }

    $Translate = New-Object -ComObject NameTranslate

    try {
        Invoke-Method $Translate "Init" (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] { 
        Write-Verbose "Error with translate init in Convert-ADName: $_"
    }

    Set-Property $Translate "ChaseReferral" (0x60)

    try {
        Invoke-Method $Translate "Set" ($NameTypes[$InputType], $ObjectName)
        (Invoke-Method $Translate "Get" ($NameTypes[$OutputType]))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        Write-Verbose "Error with translate Set/Get in Convert-ADName: $_"
    }
}

function ConvertFrom-UACValue {
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        $Value,

        [Switch]
        $ShowAll
    )

    begin {
        # values from https://support.microsoft.com/en-us/kb/305144
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("ACCOUNTDISABLE", 2)
        $UACValues.Add("HOMEDIR_REQUIRED", 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add("PASSWD_NOTREQD", 32)
        $UACValues.Add("PASSWD_CANT_CHANGE", 64)
        $UACValues.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $UACValues.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $UACValues.Add("NORMAL_ACCOUNT", 512)
        $UACValues.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $UACValues.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $UACValues.Add("SERVER_TRUST_ACCOUNT", 8192)
        $UACValues.Add("DONT_EXPIRE_PASSWORD", 65536)
        $UACValues.Add("MNS_LOGON_ACCOUNT", 131072)
        $UACValues.Add("SMARTCARD_REQUIRED", 262144)
        $UACValues.Add("TRUSTED_FOR_DELEGATION", 524288)
        $UACValues.Add("NOT_DELEGATED", 1048576)
        $UACValues.Add("USE_DES_KEY_ONLY", 2097152)
        $UACValues.Add("DONT_REQ_PREAUTH", 4194304)
        $UACValues.Add("PASSWORD_EXPIRED", 8388608)
        $UACValues.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $UACValues.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    process {

        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary

        if($Value -is [Int]) {
            $IntValue = $Value
        }
        elseif ($Value -is [PSCustomObject]) {
            if($Value.useraccountcontrol) {
                $IntValue = $Value.useraccountcontrol
            }
        }
        else {
            #Write-Warning "Invalid object input for -Value : $Value"
            return $Null 
        }

        if($ShowAll) {
            foreach ($UACValue in $UACValues.GetEnumerator()) {
                if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            foreach ($UACValue in $UACValues.GetEnumerator()) {
                if( ($IntValue -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}

filter Get-Proxy {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $ENV:COMPUTERNAME
    )

    try {
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $ComputerName)
        $RegKey = $Reg.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
        $ProxyServer = $RegKey.GetValue('ProxyServer')
        $AutoConfigURL = $RegKey.GetValue('AutoConfigURL')

        $Wpad = ""
        if($AutoConfigURL -and ($AutoConfigURL -ne "")) {
            try {
                $Wpad = (New-Object Net.Webclient).DownloadString($AutoConfigURL)
            }
            catch {
                #Write-Warning "Error connecting to AutoConfigURL : $AutoConfigURL"
            }
        }
        
        if($ProxyServer -or $AutoConfigUrl) {

            $Properties = @{
                'ProxyServer' = $ProxyServer
                'AutoConfigURL' = $AutoConfigURL
                'Wpad' = $Wpad
            }
            
            New-Object -TypeName PSObject -Property $Properties
        }
        else {
            Write-Warning "No proxy settings found for $ComputerName"
        }
    }
    catch {
        Write-Warning "Error enumerating proxy settings for $ComputerName : $_"
    }
}

function Request-SPNTicket {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        
        [Alias('EncryptedPart')]
        [Switch]
        $EncPart
    )

    begin {
        Add-Type -AssemblyName System.IdentityModel
    }

    process {
        ForEach($UserSPN in $SPN) {
            Write-Verbose "Requesting ticket for: $UserSPN"
            if (!$EncPart) {
                New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            else {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
                $TicketByteStream = $Ticket.GetRequest()
                if ($TicketByteStream)
                {
                    $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace "-"
                    [System.Collections.ArrayList]$Parts = ($TicketHexStream -replace '^(.*?)04820...(.*)','$2') -Split "A48201"
                    $Parts.RemoveAt($Parts.Count - 1)
                    $Parts -join "A48201"
                    break
                }
            }
        }
    }
}

function Get-PathAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $Path,

        [Switch]
        $Recurse
    )

    begin {

        function Convert-FileRight {

            # From http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights

            [CmdletBinding()]
            param(
                [Int]
                $FSR
            )

            $AccessMask = @{
              [uint32]'0x80000000' = 'GenericRead'
              [uint32]'0x40000000' = 'GenericWrite'
              [uint32]'0x20000000' = 'GenericExecute'
              [uint32]'0x10000000' = 'GenericAll'
              [uint32]'0x02000000' = 'MaximumAllowed'
              [uint32]'0x01000000' = 'AccessSystemSecurity'
              [uint32]'0x00100000' = 'Synchronize'
              [uint32]'0x00080000' = 'WriteOwner'
              [uint32]'0x00040000' = 'WriteDAC'
              [uint32]'0x00020000' = 'ReadControl'
              [uint32]'0x00010000' = 'Delete'
              [uint32]'0x00000100' = 'WriteAttributes'
              [uint32]'0x00000080' = 'ReadAttributes'
              [uint32]'0x00000040' = 'DeleteChild'
              [uint32]'0x00000020' = 'Execute/Traverse'
              [uint32]'0x00000010' = 'WriteExtendedAttributes'
              [uint32]'0x00000008' = 'ReadExtendedAttributes'
              [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
              [uint32]'0x00000002' = 'WriteData/AddFile'
              [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            $SimplePermissions = @{
              [uint32]'0x1f01ff' = 'FullControl'
              [uint32]'0x0301bf' = 'Modify'
              [uint32]'0x0200a9' = 'ReadAndExecute'
              [uint32]'0x02019f' = 'ReadAndWrite'
              [uint32]'0x020089' = 'Read'
              [uint32]'0x000116' = 'Write'
            }

            $Permissions = @()

            # get simple permission
            $Permissions += $SimplePermissions.Keys |  % {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }

            # get remaining extended permissions
            $Permissions += $AccessMask.Keys |
                            ? { $FSR -band $_ } |
                            % { $AccessMask[$_] }

            ($Permissions | ?{$_}) -join ","
        }
    }

    process {

        try {
            $ACL = Get-Acl -Path $Path

            [String]$PathOwner = $ACL.Owner

            $ACL.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]) | ForEach-Object {

                $Names = @()
                if ($_.IdentityReference -match '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+') {
                    $Object = Get-ADObject -SID $_.IdentityReference
                    $Names = @()
                    $SIDs = @($Object.objectsid)

                    if ($Recurse -and (@('268435456','268435457','536870912','536870913') -contains $Object.samAccountType)) {
                        $SIDs += Get-ThisThingGroupMember -SID $Object.objectsid | Select-Object -ExpandProperty MemberSid
                    }

                    $SIDs | ForEach-Object {
                        $Names += ,@($_, (Convert-SidToName $_))
                    }
                }
                else {
                    $Names += ,@($_.IdentityReference.Value, (Convert-SidToName $_.IdentityReference.Value))
                }

                ForEach($Name in $Names) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $Path
                    $Out | Add-Member Noteproperty 'PathOwner' $PathOwner
                    $Out | Add-Member Noteproperty 'FileSystemRights' (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name[1]
                    $Out | Add-Member Noteproperty 'IdentitySID' $Name[0]
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out
                }
            }
        }
        catch {
            #Write-Warning $_
        }
    }
}

filter Get-NameField {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Object]
        $Object,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $DnsHostName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $Name
    )

    if($PSBoundParameters['DnsHostName']) {
        $DnsHostName
    }
    elseif($PSBoundParameters['Name']) {
        $Name
    }
    elseif($Object) {
        if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
            # objects from Get-ThisThingComputer
            $Object.dnshostname
        }
        elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
            # objects from Get-ThisThingDomainController
            $Object.name
        }
        else {
            # strings and catch alls
            $Object
        }
    }
    else {
        return $Null
    }
}

function Convert-LDAPProperty {
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}

filter Get-DomainSearcher {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(-not $Credential) {
        if(-not $Domain) {
            $Domain = (Get-ThisThingDomain).name
        }
        elseif(-not $DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC to reflect queries through
                $DomainController = ((Get-ThisThingDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $DomainController) {
        # if a DC isn't specified
        try {
            $DomainController = ((Get-ThisThingDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += '/'
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ','
    }

    if($ADSpath) {
        if($ADSpath -Match '^GC://') {
            # if we're searching the global catalog
            $DN = $AdsPath.ToUpper().Trim('/')
            $SearchString = ''
        }
        else {
            if($ADSpath -match '^LDAP://') {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ''
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher.CacheResults = $False
    $Searcher
}

filter Convert-DNSRecord {
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
        [Byte[]]
        $DNSRecord
    )

    function Get-Name {
        # modified decodeName from https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
        [CmdletBinding()]
        param(
            [Byte[]]
            $Raw
        )

        [Int]$Length = $Raw[0]
        [Int]$Segments = $Raw[1]
        [Int]$Index =  2
        [String]$Name  = ""

        while ($Segments-- -gt 0)
        {
            [Int]$SegmentLength = $Raw[$Index++]
            while ($SegmentLength-- -gt 0) {
                $Name += [Char]$Raw[$Index++]
            }
            $Name += "."
        }
        $Name
    }

    $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
    $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
    $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

    $TTLRaw = $DNSRecord[12..15]
    # reverse for big endian
    $Null = [array]::Reverse($TTLRaw)
    $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

    $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
    if($Age -ne 0) {
        $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
    }
    else {
        $TimeStamp = "[static]"
    }

    $DNSRecordObject = New-Object PSObject

    if($RDataType -eq 1) {
        $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
        $Data = $IP
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
    }

    elseif($RDataType -eq 2) {
        $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
        $Data = $NSName
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
    }

    elseif($RDataType -eq 5) {
        $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
        $Data = $Alias
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
    }

    elseif($RDataType -eq 6) {
        # TODO: how to implement properly? nested object?
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
    }

    elseif($RDataType -eq 12) {
        $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
        $Data = $Ptr
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
    }

    elseif($RDataType -eq 13) {
        # TODO: how to implement properly? nested object?
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
    }

    elseif($RDataType -eq 15) {
        # TODO: how to implement properly? nested object?
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
    }

    elseif($RDataType -eq 16) {

        [string]$TXT  = ""
        [int]$SegmentLength = $DNSRecord[24]
        $Index = 25
        while ($SegmentLength-- -gt 0) {
            $TXT += [char]$DNSRecord[$index++]
        }

        $Data = $TXT
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
    }

    elseif($RDataType -eq 28) {
        # TODO: how to implement properly? nested object?
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
    }

    elseif($RDataType -eq 33) {
        # TODO: how to implement properly? nested object?
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
    }

    else {
        $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
        $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
    }

    $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
    $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
    $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
    $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
    $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
    $DNSRecordObject
}

filter Get-DNSZone {
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential,

        [Switch]
        $FullData
    )

    $DNSSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    $DNSSearcher.filter="(objectClass=dnsZone)"

    if($DNSSearcher) {
        $Results = $DNSSearcher.FindAll()
        $Results | Where-Object {$_} | ForEach-Object {
            # convert/process the LDAP fields for each result
            $Properties = Convert-LDAPProperty -Properties $_.Properties
            $Properties | Add-Member NoteProperty 'ZoneName' $Properties.name

            if ($FullData) {
                $Properties
            }
            else {
                $Properties | Select-Object ZoneName,distinguishedname,whencreated,whenchanged
            }
        }
        $Results.dispose()
        $DNSSearcher.dispose()
    }

    $DNSSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential -ADSprefix "CN=MicrosoftDNS,DC=DomainDnsZones"
    $DNSSearcher.filter="(objectClass=dnsZone)"

    if($DNSSearcher) {
        $Results = $DNSSearcher.FindAll()
        $Results | Where-Object {$_} | ForEach-Object {
            # convert/process the LDAP fields for each result
            $Properties = Convert-LDAPProperty -Properties $_.Properties
            $Properties | Add-Member NoteProperty 'ZoneName' $Properties.name

            if ($FullData) {
                $Properties
            }
            else {
                $Properties | Select-Object ZoneName,distinguishedname,whencreated,whenchanged
            }
        }
        $Results.dispose()
        $DNSSearcher.dispose()
    }
}

filter Get-DNSRecord {
    param(
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$True, Mandatory=$True)]
        [String]
        $ZoneName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    $DNSSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential -ADSprefix "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
    $DNSSearcher.filter="(objectClass=dnsNode)"

    if($DNSSearcher) {
        $Results = $DNSSearcher.FindAll()
        $Results | Where-Object {$_} | ForEach-Object {
            try {
                # convert/process the LDAP fields for each result
                $Properties = Convert-LDAPProperty -Properties $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                $Properties | Add-Member NoteProperty 'ZoneName' $ZoneName

                # convert the record and extract the properties
                if ($Properties.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                    # TODO: handle multiple nested records properly?
                    $Record = Convert-DNSRecord -DNSRecord $Properties.dnsrecord[0]
                }
                else {
                    $Record = Convert-DNSRecord -DNSRecord $Properties.dnsrecord
                }

                if($Record) {
                    $Record.psobject.properties | ForEach-Object {
                        $Properties | Add-Member NoteProperty $_.Name $_.Value
                    }
                }

                $Properties
            }
            catch {
                #Write-Warning "ERROR: $_"
                $Properties
            }
        }
        $Results.dispose()
        $DNSSearcher.dispose()
    }
}

filter Get-ThisThingDomain {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-ThisThingDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
   
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}

filter Get-ThisThingForest {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-ThisThingForest"

        if(!$Forest) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Forest = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Forest' from -Credential"
        }
   
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch {
            Write-Verbose "The specified forest '$Forest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Forest) {
        $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
        try {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
        }
        catch {
            Write-Verbose "The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust."
            return $Null
        }
    }
    else {
        # otherwise use the current forest
        $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }

    if($ForestObject) {
        # get the SID of the forest root
        $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $Parts = $ForestSid -Split "-"
        $ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
        $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
        $ForestObject
    }
}

filter Get-ThisThingForestDomain {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    $ForestObject = Get-ThisThingForest -Forest $Forest -Credential $Credential

    if($ForestObject) {
        $ForestObject.Domains
    }
}

filter Get-ThisThingForestCatalog {  
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    $ForestObject = Get-ThisThingForest -Forest $Forest -Credential $Credential

    if($ForestObject) {
        $ForestObject.FindAllGlobalCatalogs()
    }
}

filter Get-ThisThingDomainController {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($LDAP -or $DomainController) {
        # filter string to return all domain controllers
        Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    else {
        $FoundDomain = Get-ThisThingDomain -Domain $Domain -Credential $Credential
        if($FoundDomain) {
            $Founddomain.DomainControllers
        }
    }
}

function Get-ThisThingUser {
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    }

    process {
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $Results = $UserSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                $User = Convert-LDAPProperty -Properties $_.Properties
                $User.PSObject.TypeNames.Add('PowerView.User')
                $User
            }
            $Results.dispose()
            $UserSearcher.dispose()
        }
    }
}

function Add-NetUser {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'backdoor',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName = 'localhost',

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain
    )

    if ($Domain) {

        $DomainObject = Get-ThisThingDomain -Domain $Domain
        if(-not $DomainObject) {
            #Write-Warning "Error in grabbing $Domain object"
            return $Null
        }

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
        # get the domain context
        $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain), $DomainObject

        # create the user object
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $Context

        # set user properties
        $User.Name = $UserName
        $User.SamAccountName = $UserName
        $User.PasswordNotRequired = $False
        $User.SetPassword($Password)
        $User.Enabled = $True

        Write-Verbose "Creating user $UserName to with password '$Password' in domain $Domain"

        try {
            # commit the user
            $User.Save()
            "[*] User $UserName successfully created in domain $Domain"
        }
        catch {
            #Write-Warning '[!] User already exists!'
            return
        }
    }
    else {
        
        Write-Verbose "Creating user $UserName to with password '$Password' on $ComputerName"

        # if it's not a domain add, it's a local machine add
        $ObjOu = [ADSI]"WinNT://$ComputerName"
        $ObjUser = $ObjOu.Create('User', $UserName)
        $ObjUser.SetPassword($Password)

        # commit the changes to the local machine
        try {
            $Null = $ObjUser.SetInfo()
            "[*] User $UserName successfully created on host $ComputerName"
        }
        catch {
            #Write-Warning '[!] Account already exists!'
            return
        }
    }

    # if a group is specified, invoke Add-NetGroupUser and return its value
    if ($GroupName) {
        # if we're adding the user to a domain
        if ($Domain) {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -Domain $Domain
            "[*] User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else {
            Add-NetGroupUser -UserName $UserName -GroupName $GroupName -ComputerName $ComputerName
            "[*] User $UserName successfully added to group $GroupName on host $ComputerName"
        }
    }
}

function Add-NetGroupUser {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName,

        [ValidateNotNullOrEmpty()]
        [Alias('HostName')]
        [String]
        $ComputerName,

        [String]
        $Domain
    )

    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # if we're adding to a remote host's local group, use the WinNT provider
    if($ComputerName -and ($ComputerName -ne "localhost")) {
        try {
            Write-Verbose "Adding user $UserName to $GroupName on host $ComputerName"
            ([ADSI]"WinNT://$ComputerName/$GroupName,group").add("WinNT://$ComputerName/$UserName,user")
            "[*] User $UserName successfully added to group $GroupName on $ComputerName"
        }
        catch {
            Write-Warning "[!] Error adding user $UserName to group $GroupName on $ComputerName"
            return
        }
    }

    # otherwise it's a local machine or domain add
    else {
        try {
            if ($Domain) {
                Write-Verbose "Adding user $UserName to $GroupName on domain $Domain"
                $CT = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $DomainObject = Get-ThisThingDomain -Domain $Domain
                if(-not $DomainObject) {
                    return $Null
                }
                # get the full principal context
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $CT, $DomainObject            
            }
            else {
                # otherwise, get the local machine context
                Write-Verbose "Adding user $UserName to $GroupName on localhost"
                $Context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Env:ComputerName)
            }

            # find the particular group
            $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($Context,$GroupName)

            # add the particular user to the group
            $Group.Members.add($Context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

            # commit the changes
            $Group.Save()
        }
        catch {
            Write-Warning "Error adding $UserName to $GroupName : $_"
        }
    }
}

function Get-UserProperty {
    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,
        
        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Properties) {
        # extract out the set of all properties for each object
        $Properties = ,"name" + $Properties
        Get-ThisThingUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential | Select-Object -Property $Properties
    }
    else {
        # extract out just the property names
        Get-ThisThingUser -Domain $Domain -DomainController $DomainController -PageSize $PageSize -Credential $Credential | Select-Object -First 1 | Get-Member -MemberType *Property | Select-Object -Property 'Name'
    }
}

filter Find-UserField {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $SearchTerm = 'pass',

        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )
 
    Get-ThisThingUser -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
}

filter Get-UserEvent {
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName = $Env:ComputerName,

        [String]
        [ValidateSet("logon","tgt","all")]
        $EventType = "logon",

        [DateTime]
        $DateStart = [DateTime]::Today.AddDays(-5),

        [Management.Automation.PSCredential]
        $Credential
    )

    if($EventType.ToLower() -like "logon") {
        [Int32[]]$ID = @(4624)
    }
    elseif($EventType.ToLower() -like "tgt") {
        [Int32[]]$ID = @(4768)
    }
    else {
        [Int32[]]$ID = @(4624, 4768)
    }

    if($Credential) {
        Write-Verbose "Using alternative credentials"
        $Arguments = @{
            'ComputerName' = $ComputerName;
            'Credential' = $Credential;
            'FilterHashTable' = @{ LogName = 'Security'; ID=$ID; StartTime=$DateStart};
            'ErrorAction' = 'SilentlyContinue';
        }
    }
    else {
        $Arguments = @{
            'ComputerName' = $ComputerName;
            'FilterHashTable' = @{ LogName = 'Security'; ID=$ID; StartTime=$DateStart};
            'ErrorAction' = 'SilentlyContinue';            
        }
    }

    # grab all events matching our filter for the specified host
    Get-WinEvent @Arguments | ForEach-Object {

        if($ID -contains 4624) {    
            # first parse and check the logon event type. This could be later adapted and tested for RDP logons (type 10)
            if($_.message -match '(?s)(?<=Logon Type:).*?(?=(Impersonation Level:|New Logon:))') {
                if($Matches) {
                    $LogonType = $Matches[0].trim()
                    $Matches = $Null
                }
            }
            else {
                $LogonType = ""
            }

            # interactive logons or domain logons
            if (($LogonType -eq 2) -or ($LogonType -eq 3)) {
                try {
                    # parse and store the account used and the address they came from
                    if($_.message -match '(?s)(?<=New Logon:).*?(?=Process Information:)') {
                        if($Matches) {
                            $UserName = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Domain = $Matches[0].split("`n")[3].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }
                    if($_.message -match '(?s)(?<=Network Information:).*?(?=Source Port:)') {
                        if($Matches) {
                            $Address = $Matches[0].split("`n")[2].split(":")[1].trim()
                            $Matches = $Null
                        }
                    }

                    # only add if there was account information not for a machine or anonymous logon
                    if ($UserName -and (-not $UserName.endsWith('$')) -and ($UserName -ne 'ANONYMOUS LOGON')) {
                        $LogonEventProperties = @{
                            'Domain' = $Domain
                            'ComputerName' = $ComputerName
                            'Username' = $UserName
                            'Address' = $Address
                            'ID' = '4624'
                            'LogonType' = $LogonType
                            'Time' = $_.TimeCreated
                        }
                        New-Object -TypeName PSObject -Property $LogonEventProperties
                    }
                }
                catch {
                    Write-Verbose "Error parsing event logs: $_"
                }
            }
        }
        if($ID -contains 4768) {
            # the TGT event type
            try {
                if($_.message -match '(?s)(?<=Account Information:).*?(?=Service Information:)') {
                    if($Matches) {
                        $Username = $Matches[0].split("`n")[1].split(":")[1].trim()
                        $Domain = $Matches[0].split("`n")[2].split(":")[1].trim()
                        $Matches = $Null
                    }
                }

                if($_.message -match '(?s)(?<=Network Information:).*?(?=Additional Information:)') {
                    if($Matches) {
                        $Address = $Matches[0].split("`n")[1].split(":")[-1].trim()
                        $Matches = $Null
                    }
                }

                $LogonEventProperties = @{
                    'Domain' = $Domain
                    'ComputerName' = $ComputerName
                    'Username' = $UserName
                    'Address' = $Address
                    'ID' = '4768'
                    'LogonType' = ''
                    'Time' = $_.TimeCreated
                }

                New-Object -TypeName PSObject -Property $LogonEventProperties
            }
            catch {
                Write-Verbose "Error parsing event logs: $_"
            }
        }
    }
}

function Get-ObjectAcl {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $SamAccountName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $Name = "*",

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $DistinguishedName = "*",

        [Switch]
        $ResolveGUIDs,

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers")]
        $RightsFilter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -ADSprefix $ADSprefix -PageSize $PageSize 

        # get a GUID -> name mapping
        if($ResolveGUIDs) {
            $GUIDs = Get-GUIDMap -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }

    process {

        if ($Searcher) {

            if($SamAccountName) {
                $Searcher.filter="(&(samaccountname=$SamAccountName)(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
            else {
                $Searcher.filter="(&(name=$Name)(distinguishedname=$DistinguishedName)$Filter)"  
            }
  
            try {
                $Results = $Searcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Object = [adsi]($_.path)

                    if($Object.distinguishedname) {
                        $Access = $Object.PsBase.ObjectSecurity.access
                        $Access | ForEach-Object {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]

                            if($Object.objectsid[0]){
                                $S = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                            }
                            else {
                                $S = $Null
                            }
                            
                            $_ | Add-Member NoteProperty 'ObjectSID' $S
                            $_
                        }
                    }
                } | ForEach-Object {
                    if($RightsFilter) {
                        $GuidFilter = Switch ($RightsFilter) {
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            Default { "00000000-0000-0000-0000-000000000000"}
                        }
                        if($_.ObjectType -eq $GuidFilter) { $_ }
                    }
                    else {
                        $_
                    }
                } | ForEach-Object {
                    if($GUIDs) {
                        # if we're resolving GUIDs, map them them to the resolved hash table
                        $AclProperties = @{}
                        $_.psobject.properties | ForEach-Object {
                            if( ($_.Name -eq 'ObjectType') -or ($_.Name -eq 'InheritedObjectType') ) {
                                try {
                                    $AclProperties[$_.Name] = $GUIDS[$_.Value.toString()]
                                }
                                catch {
                                    $AclProperties[$_.Name] = $_.Value
                                }
                            }
                            else {
                                $AclProperties[$_.Name] = $_.Value
                            }
                        }
                        New-Object -TypeName PSObject -Property $AclProperties
                    }
                    else { $_ }
                }
                $Results.dispose()
                $Searcher.dispose()
            }
            catch {
                #Write-Warning $_
            }
        }
    }
}

function Add-ObjectAcl {
    [CmdletBinding()]
    Param (
        [String]
        $TargetSamAccountName,

        [String]
        $TargetName = "*",

        [Alias('DN')]
        [String]
        $TargetDistinguishedName = "*",

        [String]
        $TargetFilter,

        [String]
        $TargetADSpath,

        [String]
        $TargetADSprefix,

        [String]
        [ValidatePattern('^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+')]
        $PrincipalSID,

        [String]
        $PrincipalName,

        [String]
        $PrincipalSamAccountName,

        [String]
        [ValidateSet("All","ResetPassword","WriteMembers","DCSync")]
        $Rights = "All",

        [String]
        $RightsGUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $Searcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $TargetADSpath -ADSprefix $TargetADSprefix -PageSize $PageSize

        if($PrincipalSID) {
            $ResolvedPrincipalSID = $PrincipalSID
        }
        else {
            $Principal = Get-ADObject -Domain $Domain -DomainController $DomainController -Name $PrincipalName -SamAccountName $PrincipalSamAccountName -PageSize $PageSize
            
            if(!$Principal) {
                throw "Error resolving principal"
            }
            $ResolvedPrincipalSID = $Principal.objectsid
        }
        if(!$ResolvedPrincipalSID) {
            throw "Error resolving principal"
        }
    }

    process {

        if ($Searcher) {

            if($TargetSamAccountName) {
                $Searcher.filter="(&(samaccountname=$TargetSamAccountName)(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
            else {
                $Searcher.filter="(&(name=$TargetName)(distinguishedname=$TargetDistinguishedName)$TargetFilter)"  
            }
  
            try {
                $Results = $Searcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {

                    # adapted from https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects

                    $TargetDN = $_.Properties.distinguishedname

                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$ResolvedPrincipalSID)
                    $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
                    $ControlType = [System.Security.AccessControl.AccessControlType] "Allow"
                    $ACEs = @()

                    if($RightsGUID) {
                        $GUIDs = @($RightsGUID)
                    }
                    else {
                        $GUIDs = Switch ($Rights) {
                            # ResetPassword doesn't need to know the user's current password
                            "ResetPassword" { "00299570-246d-11d0-a768-00aa006e0529" }
                            # allows for the modification of group membership
                            "WriteMembers" { "bf9679c0-0de6-11d0-a285-00aa003049e2" }
                            # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                            # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                            # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                            #   when applied to a domain's ACL, allows for the use of DCSync
                            "DCSync" { "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c"}
                        }
                    }

                    if($GUIDs) {
                        foreach($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$NewGUID,$InheritanceType
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity,$ADRights,$ControlType,$InheritanceType
                    }

                    Write-Verbose "Granting principal $ResolvedPrincipalSID '$Rights' on $($_.Properties.distinguishedname)"

                    try {
                        # add all the new ACEs to the specified object
                        ForEach ($ACE in $ACEs) {
                            Write-Verbose "Granting principal $ResolvedPrincipalSID '$($ACE.ObjectType)' rights on $($_.Properties.distinguishedname)"
                            $Object = [adsi]($_.path)
                            $Object.PsBase.ObjectSecurity.AddAccessRule($ACE)
                            $Object.PsBase.commitchanges()
                        }
                    }
                    catch {
                        Write-Warning "Error granting principal $ResolvedPrincipalSID '$Rights' on $TargetDN : $_"
                    }
                }
                $Results.dispose()
                $Searcher.dispose()
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}

function Invoke-ACLScanner {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [String]
        $Name = "*",

        [Alias('DN')]
        [String]
        $DistinguishedName = "*",

        [String]
        $Filter,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveGUIDs,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    # Get all domain ACLs with the appropriate parameters
    Get-ObjectACL @PSBoundParameters | ForEach-Object {
        # add in the translated SID for the object identity
        $_ | Add-Member Noteproperty 'IdentitySID' ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
        $_
    } | Where-Object {
        # check for any ACLs with SIDs > -1000
        try {
            # TODO: change this to a regex for speedup?
            [int]($_.IdentitySid.split("-")[-1]) -ge 1000
        }
        catch {}
    } | Where-Object {
        # filter for modifiable rights
        ($_.ActiveDirectoryRights -eq "GenericAll") -or ($_.ActiveDirectoryRights -match "Write") -or ($_.ActiveDirectoryRights -match "Create") -or ($_.ActiveDirectoryRights -match "Delete") -or (($_.ActiveDirectoryRights -match "ExtendedRight") -and ($_.AccessControlType -eq "Allow"))
    }
}

filter Get-GUIDMap {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    $SchemaPath = (Get-ThisThingForest).schema.name

    $SchemaSearcher = Get-DomainSearcher -ADSpath $SchemaPath -DomainController $DomainController -PageSize $PageSize
    if($SchemaSearcher) {
        $SchemaSearcher.filter = "(schemaIDGUID=*)"
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            $Results.dispose()
            $SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose "Error in building GUID map: $_"
        }
    }

    $RightsSearcher = Get-DomainSearcher -ADSpath $SchemaPath.replace("Schema","Extended-Rights") -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    if ($RightsSearcher) {
        $RightsSearcher.filter = "(objectClass=controlAccessRight)"
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            $Results.dispose()
            $RightsSearcher.dispose()
        }
        catch {
            Write-Verbose "Error in building GUID map: $_"
        }
    }

    $GUIDs
}

function Get-ThisThingComputer {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $SiteName,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if multiple computer names are passed on the pipeline
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize -Credential $Credential
    }

    process {

        if ($CompSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            # set the filters for the seracher if it exists
            if($Printers) {
                Write-Verbose "Searching for printers"
                # $CompSearcher.filter="(&(objectCategory=printQueue)$Filter)"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if($SiteName) {
                $Filter += "(serverreferencebl=$SiteName)"
            }

            $CompFilter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"
            Write-Verbose "Get-ThisThingComputer filter : '$CompFilter'"
            $CompSearcher.filter = $CompFilter

            try {
                $Results = $CompSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        # TODO: how can these results be piped to ping for a speedup?
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        # return full data objects
                        if ($FullData) {
                            # convert/process the LDAP fields for each result
                            $Computer = Convert-LDAPProperty -Properties $_.Properties
                            $Computer.PSObject.TypeNames.Add('PowerView.Computer')
                            $Computer
                        }
                        else {
                            # otherwise we're just returning the DNS host name
                            $_.properties.dnshostname
                        }
                    }
                }
                $Results.dispose()
                $CompSearcher.dispose()
            }
            catch {
                #Write-Warning "Error: $_"
            }
        }
    }
}

function Get-ADObject {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $ReturnRaw,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )
    process {
        if($SID) {
            # if a SID is passed, try to resolve it to a reachable domain name for the searcher
            try {
                $Name = Convert-SidToName $SID
                if($Name) {
                    $Canonical = Convert-ADName -ObjectName $Name -InputType NT4 -OutputType Canonical
                    if($Canonical) {
                        $Domain = $Canonical.split("/")[0]
                    }
                    else {
                        #Write-Warning "Error resolving SID '$SID'"
                        return $Null
                    }
                }
            }
            catch {
                #Write-Warning "Error resolving SID '$SID' : $_"
                return $Null
            }
        }

        $ObjectSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($ObjectSearcher) {
            if($SID) {
                $ObjectSearcher.filter = "(&(objectsid=$SID)$Filter)"
            }
            elseif($Name) {
                $ObjectSearcher.filter = "(&(name=$Name)$Filter)"
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = "(&(samAccountName=$SamAccountName)$Filter)"
            }

            $Results = $ObjectSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                if($ReturnRaw) {
                    $_
                }
                else {
                    # convert/process the LDAP fields for each result
                    Convert-LDAPProperty -Properties $_.Properties
                }
            }
            $Results.dispose()
            $ObjectSearcher.dispose()
        }
    }
}

function Set-ADObject {
    [CmdletBinding()]
    Param (
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Parameter(Mandatory = $True)]
        [String]
        $PropertyName,

        $PropertyValue,

        [Int]
        $PropertyXorValue,

        [Switch]
        $ClearValue,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    $Arguments = @{
        'SID' = $SID
        'Name' = $Name
        'SamAccountName' = $SamAccountName
        'Domain' = $Domain
        'DomainController' = $DomainController
        'Filter' = $Filter
        'PageSize' = $PageSize
        'Credential' = $Credential
    }
    # splat the appropriate arguments to Get-ADObject
    $RawObject = Get-ADObject -ReturnRaw @Arguments
    
    try {
        # get the modifiable object for this search result
        $Entry = $RawObject.GetDirectoryEntry()
        
        if($ClearValue) {
            Write-Verbose "Clearing value"
            $Entry.$PropertyName.clear()
            $Entry.commitchanges()
        }

        elseif($PropertyXorValue) {
            $TypeName = $Entry.$PropertyName[0].GetType().name

            # UAC value references- https://support.microsoft.com/en-us/kb/305144
            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue 
            $Entry.$PropertyName = $PropertyValue -as $TypeName       
            $Entry.commitchanges()     
        }

        else {
            $Entry.put($PropertyName, $PropertyValue)
            $Entry.setinfo()
        }
    }
    catch {
        Write-Warning "Error setting property $PropertyName to value '$PropertyValue' for object $($RawObject.Properties.samaccountname) : $_"
    }
}

function Invoke-DowngradeAccount {
    [CmdletBinding()]
    Param (
        [Parameter(ParameterSetName = 'SamAccountName', Position=0, ValueFromPipeline=$True)]
        [String]
        $SamAccountName,

        [Parameter(ParameterSetName = 'Name')]
        [String]
        $Name,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $Filter,

        [Switch]
        $Repair,

        [Management.Automation.PSCredential]
        $Credential
    )

    process {
        $Arguments = @{
            'SamAccountName' = $SamAccountName
            'Name' = $Name
            'Domain' = $Domain
            'DomainController' = $DomainController
            'Filter' = $Filter
            'Credential' = $Credential
        }

        # splat the appropriate arguments to Get-ADObject
        $UACValues = Get-ADObject @Arguments | select useraccountcontrol | ConvertFrom-UACValue

        if($Repair) {

            if($UACValues.Keys -contains "ENCRYPTED_TEXT_PWD_ALLOWED") {
                # if reversible encryption is set, unset it
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            # unset the forced password change
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue -1
        }

        else {

            if($UACValues.Keys -contains "DONT_EXPIRE_PASSWORD") {
                # if the password is set to never expire, unset
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 65536
            }

            if($UACValues.Keys -notcontains "ENCRYPTED_TEXT_PWD_ALLOWED") {
                # if reversible encryption is not set, set it
                Set-ADObject @Arguments -PropertyName useraccountcontrol -PropertyXorValue 128
            }

            # force the password to be changed on next login
            Set-ADObject @Arguments -PropertyName pwdlastset -PropertyValue 0
        }
    }
}

function Get-ComputerProperty {
    [CmdletBinding()]
    param(
        [String[]]
        $Properties,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Properties) {
        # extract out the set of all properties for each object
        $Properties = ,"name" + $Properties | Sort-Object -Unique
        Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize | Select-Object -Property $Properties
    }
    else {
        # extract out just the property names
        Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -PageSize $PageSize | Select-Object -first 1 | Get-Member -MemberType *Property | Select-Object -Property "Name"
    }
}

function Find-ComputerField {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Term')]
        [String]
        $SearchTerm = 'pass',

        [Alias('Field')]
        [String]
        $SearchField = 'description',

        [String]
        $ADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    process {
        Get-ThisThingComputer -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -FullData -Filter "($SearchField=*$SearchTerm*)" -PageSize $PageSize | Select-Object samaccountname,$SearchField
    }
}

function Get-ThisThingOU {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $OUName = '*',

        [String]
        $GUID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $OUSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }
    process {
        if ($OUSearcher) {
            if ($GUID) {
                # if we're filtering for a GUID in .gplink
                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName)(gplink=*$GUID*))"
            }
            else {
                $OUSearcher.filter="(&(objectCategory=organizationalUnit)(name=$OUName))"
            }

            try {
                $Results = $OUSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        $OU = Convert-LDAPProperty -Properties $_.Properties
                        $OU.PSObject.TypeNames.Add('PowerView.OU')
                        $OU
                    }
                    else { 
                        # otherwise just returning the ADS paths of the OUs
                        $_.properties.adspath
                    }
                }
                $Results.dispose()
                $OUSearcher.dispose()
            }
            catch {
                Write-Warning $_
            }
        }
    }
}

function Get-ThisThingSite {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $GUID,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $SiteSearcher = Get-DomainSearcher -ADSpath $ADSpath -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSprefix "CN=Sites,CN=Configuration" -PageSize $PageSize
    }
    process {
        if($SiteSearcher) {

            if ($GUID) {
                # if we're filtering for a GUID in .gplink
                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName)(gplink=*$GUID*))"
            }
            else {
                $SiteSearcher.filter="(&(objectCategory=site)(name=$SiteName))"
            }
            
            try {
                $Results = $SiteSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        $Site = Convert-LDAPProperty -Properties $_.Properties
                        $Site.PSObject.TypeNames.Add('PowerView.Site')
                        $Site
                    }
                    else {
                        # otherwise just return the site name
                        $_.properties.name
                    }
                }
                $Results.dispose()
                $SiteSearcher.dispose()
            }
            catch {
                Write-Verbose $_
            }
        }
    }
}

function Get-ThisThingSubnet {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SiteName = "*",

        [String]
        $Domain,

        [String]
        $ADSpath,

        [String]
        $DomainController,

        [Switch]
        $FullData,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $SubnetSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -ADSprefix "CN=Subnets,CN=Sites,CN=Configuration" -PageSize $PageSize
    }

    process {
        if($SubnetSearcher) {

            $SubnetSearcher.filter="(&(objectCategory=subnet))"

            try {
                $Results = $SubnetSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties | Where-Object { $_.siteobject -match "CN=$SiteName" }
                    }
                    else {
                        # otherwise just return the subnet name and site name
                        if ( ($SiteName -and ($_.properties.siteobject -match "CN=$SiteName,")) -or ($SiteName -eq '*')) {

                            $SubnetProperties = @{
                                'Subnet' = $_.properties.name[0]
                            }
                            try {
                                $SubnetProperties['Site'] = ($_.properties.siteobject[0]).split(",")[0]
                            }
                            catch {
                                $SubnetProperties['Site'] = 'Error'
                            }

                            New-Object -TypeName PSObject -Property $SubnetProperties
                        }
                    }
                }
                $Results.dispose()
                $SubnetSearcher.dispose()
            }
            catch {
                Write-Warning $_
            }
        }
    }
}

function Get-DomainSID {


    param(
        [String]
        $Domain,

        [String]
        $DomainController
    )

    $DCSID = Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)' | Select-Object -First 1 -ExpandProperty objectsid
    if($DCSID) {
        $DCSID.Substring(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "Error extracting domain SID for $Domain"
    }
}

function Get-ThisThingGroup {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = '*',

        [String]
        $SID,

        [String]
        $UserName,

        [String]
        $Filter,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $AdminCount,

        [Switch]
        $FullData,

        [Switch]
        $RawSids,

        [Switch]
        $AllTypes,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
        if (!$AllTypes)
        {
          $Filter += "(groupType:1.2.840.113556.1.4.803:=2147483648)"
        }
    }

    process {
        if($GroupSearcher) {

            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            if ($UserName) {
                # get the raw user object
                $User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -Credential $Credential -ReturnRaw -PageSize $PageSize | Select-Object -First 1

                if($User) {
                    # convert the user to a directory entry
                    $UserDirectoryEntry = $User.GetDirectoryEntry()

                    # cause the cache to calculate the token groups for the user
                    $UserDirectoryEntry.RefreshCache("tokenGroups")

                    $UserDirectoryEntry.TokenGroups | ForEach-Object {
                        # convert the token group sid
                        $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value

                        # ignore the built in groups
                        if($GroupSid -notmatch '^S-1-5-32-.*') {
                            if($FullData) {
                                $Group = Get-ADObject -SID $GroupSid -PageSize $PageSize -Domain $Domain -DomainController $DomainController -Credential $Credential
                                $Group.PSObject.TypeNames.Add('PowerView.Group')
                                $Group
                            }
                            else {
                                if($RawSids) {
                                    $GroupSid
                                }
                                else {
                                    Convert-SidToName -SID $GroupSid
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Warning "UserName '$UserName' failed to resolve."
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    $GroupSearcher.filter = "(&(objectCategory=group)(samaccountname=$GroupName)$Filter)"
                }

                $Results = $GroupSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    # if we're returning full data objects
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                        $Group.PSObject.TypeNames.Add('PowerView.Group')
                        $Group
                    }
                    else {
                        # otherwise we're just returning the group name
                        $_.properties.samaccountname
                    }
                }
                $Results.dispose()
                $GroupSearcher.dispose()
            }
        }
    }
}

function Get-ThisThingGroupMember {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        if($DomainController) {
            $TargetDomainController = $DomainController
        }
        else {
            $TargetDomainController = ((Get-ThisThingDomain -Credential $Credential).PdcRoleOwner).Name
        }

        if($Domain) {
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = Get-ThisThingDomain -Credential $Credential | Select-Object -ExpandProperty name
        }

        # so this isn't repeated if users are passed on the pipeline
        $GroupSearcher = Get-DomainSearcher -Domain $TargetDomain -DomainController $TargetDomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if ($GroupSearcher) {
            if ($Recurse -and $UseMatchingRule) {
                # resolve the group to a distinguishedname
                if ($GroupName) {
                    $Group = Get-ThisThingGroup -AllTypes -GroupName $GroupName -Domain $TargetDomain -DomainController $TargetDomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = Get-ThisThingGroup -AllTypes -SID $SID -Domain $TargetDomain -DomainController $TargetDomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $TargetDomain -DomainController $TargetDomainController) + "-512"
                    $Group = Get-ThisThingGroup -AllTypes -SID $SID -Domain $TargetDomain -DomainController $TargetDomainController -Credential $Credential -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.samaccountname

                if ($GroupDN) {
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(samaccountname=$GroupName)$Filter)"
                }
                elseif ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $TargetDomain -DomainController $TargetDomainController) + "-512"
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }

                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    $Members = @()
                }

                $GroupFoundName = ''

                if ($Result) {
                    $Members = $Result.properties.item("member")

                    if($Members.count -eq 0) {

                        $Finished = $False
                        $Bottom = 0
                        $Top = 0

                        while(!$Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            
                            $GroupSearcher.PropertiesToLoad.Clear()
                            [void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            [void]$GroupSearcher.PropertiesToLoad.Add("samaccountname")
                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like "member;range=*"
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item("samaccountname")[0]

                                if ($Members.count -eq 0) { 
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item("samaccountname")[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }
                }
                $GroupSearcher.dispose()
            }

            $Members | Where-Object {$_} | ForEach-Object {
                # if we're doing the LDAP_MATCHING_RULE_IN_CHAIN recursion
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($TargetDomainController) {
                        $Result = [adsi]"LDAP://$TargetDomainController/$_"
                    }
                    else {
                        $Result = [adsi]"LDAP://$_"
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Properties.samaccounttype

                    if ($FullData) {
                        $GroupMember = Convert-LDAPProperty -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $TargetDomain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName

                    if($Properties.objectSid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }

                    try {
                        $MemberDN = $Properties.distinguishedname[0]

                        if (($MemberDN -match 'ForeignSecurityPrincipals') -and ($MemberDN -match 'S-1-5-21')) {
                            try {
                                if(-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-SidToName -SID $MemberSID | Convert-ADName -InputType 'NT4' -OutputType 'Simple'
                                if($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "Error converting $MemberDN"
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "Error converting $MemberDN"
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = Convert-SidToName $Properties.cn[0]
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn
                        }
                    }

                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberSID' $MemberSID
                    $GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
                    $GroupMember.PSObject.TypeNames.Add('PowerView.GroupMember')
                    $GroupMember

                    # if we're doing manual recursion
                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        if($FullData) {
                            Get-ThisThingGroupMember -FullData -Domain $MemberDomain -DomainController $TargetDomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
                        }
                        else {
                            Get-ThisThingGroupMember -Domain $MemberDomain -DomainController $TargetDomainController -Credential $Credential -GroupName $MemberName -Recurse -PageSize $PageSize
                        }
                    }
                }
            }
        }
    }
}

function Get-ThisThingFileServer {

    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String[]]
        $TargetUsers,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    function SplitPath {
        # short internal helper to split UNC server paths
        param([String]$Path)

        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }
    $filter = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(scriptpath=*)(homedirectory=*)(profilepath=*))"
    Get-ThisThingUser -Domain $Domain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -Filter $filter | Where-Object {$_} | Where-Object {
            # filter for any target users
            if($TargetUsers) {
                $TargetUsers -Match $_.samAccountName
            }
            else { $True }
        } | ForEach-Object {
            # split out every potential file server path
            if($_.homedirectory) {
                SplitPath($_.homedirectory)
            }
            if($_.scriptpath) {
                SplitPath($_.scriptpath)
            }
            if($_.profilepath) {
                SplitPath($_.profilepath)
            }

        } | Where-Object {$_} | Sort-Object -Unique
}

function Get-DFSshare {
    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $Version = "All",

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    function Parse-Pkt {
        [CmdletBinding()]
        param(
            [byte[]]
            $Pkt
        )

        $bin = $Pkt
        $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
        $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
        $offset = 8
        #https://msdn.microsoft.com/en-us/library/cc227147.aspx
        $object_list = @()
        for($i=1; $i -le $blob_element_count; $i++){
               $blob_name_size_start = $offset
               $blob_name_size_end = $offset + 1
               $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)

               $blob_name_start = $blob_name_size_end + 1
               $blob_name_end = $blob_name_start + $blob_name_size - 1
               $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])

               $blob_data_size_start = $blob_name_end + 1
               $blob_data_size_end = $blob_data_size_start + 3
               $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)

               $blob_data_start = $blob_data_size_end + 1
               $blob_data_end = $blob_data_start + $blob_data_size - 1
               $blob_data = $bin[$blob_data_start..$blob_data_end]
               switch -wildcard ($blob_name) {
                "\siteroot" {  }
                "\domainroot*" {
                    # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                    # DFSRootOrLinkIDBlob
                    $root_or_link_guid_start = 0
                    $root_or_link_guid_end = 15
                    $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                    $guid = New-Object Guid(,$root_or_link_guid) # should match $guid_str
                    $prefix_size_start = $root_or_link_guid_end + 1
                    $prefix_size_end = $prefix_size_start + 1
                    $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                    $prefix_start = $prefix_size_end + 1
                    $prefix_end = $prefix_start + $prefix_size - 1
                    $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])

                    $short_prefix_size_start = $prefix_end + 1
                    $short_prefix_size_end = $short_prefix_size_start + 1
                    $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                    $short_prefix_start = $short_prefix_size_end + 1
                    $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                    $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])

                    $type_start = $short_prefix_end + 1
                    $type_end = $type_start + 3
                    $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)

                    $state_start = $type_end + 1
                    $state_end = $state_start + 3
                    $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)

                    $comment_size_start = $state_end + 1
                    $comment_size_end = $comment_size_start + 1
                    $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                    $comment_start = $comment_size_end + 1
                    $comment_end = $comment_start + $comment_size - 1
                    if ($comment_size -gt 0)  {
                        $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                    }
                    $prefix_timestamp_start = $comment_end + 1
                    $prefix_timestamp_end = $prefix_timestamp_start + 7
                    # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                    $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] #dword lowDateTime #dword highdatetime
                    $state_timestamp_start = $prefix_timestamp_end + 1
                    $state_timestamp_end = $state_timestamp_start + 7
                    $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                    $comment_timestamp_start = $state_timestamp_end + 1
                    $comment_timestamp_end = $comment_timestamp_start + 7
                    $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                    $version_start = $comment_timestamp_end  + 1
                    $version_end = $version_start + 3
                    $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)

                    # Parse rest of DFSNamespaceRootOrLinkBlob here
                    $dfs_targetlist_blob_size_start = $version_end + 1
                    $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                    $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)

                    $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                    $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                    $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                    $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                    $reserved_blob_size_end = $reserved_blob_size_start + 3
                    $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)

                    $reserved_blob_start = $reserved_blob_size_end + 1
                    $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                    $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                    $referral_ttl_start = $reserved_blob_end + 1
                    $referral_ttl_end = $referral_ttl_start + 3
                    $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)

                    #Parse DFSTargetListBlob
                    $target_count_start = 0
                    $target_count_end = $target_count_start + 3
                    $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                    $t_offset = $target_count_end + 1

                    for($j=1; $j -le $target_count; $j++){
                        $target_entry_size_start = $t_offset
                        $target_entry_size_end = $target_entry_size_start + 3
                        $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                        $target_time_stamp_start = $target_entry_size_end + 1
                        $target_time_stamp_end = $target_time_stamp_start + 7
                        # FILETIME again or special if priority rank and priority class 0
                        $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                        $target_state_start = $target_time_stamp_end + 1
                        $target_state_end = $target_state_start + 3
                        $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)

                        $target_type_start = $target_state_end + 1
                        $target_type_end = $target_type_start + 3
                        $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)

                        $server_name_size_start = $target_type_end + 1
                        $server_name_size_end = $server_name_size_start + 1
                        $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)

                        $server_name_start = $server_name_size_end + 1
                        $server_name_end = $server_name_start + $server_name_size - 1
                        $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])

                        $share_name_size_start = $server_name_end + 1
                        $share_name_size_end = $share_name_size_start + 1
                        $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                        $share_name_start = $share_name_size_end + 1
                        $share_name_end = $share_name_start + $share_name_size - 1
                        $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])

                        $target_list += "\\$server_name\$share_name"
                        $t_offset = $share_name_end + 1
                    }
                }
            }
            $offset = $blob_data_end + 1
            $dfs_pkt_properties = @{
                'Name' = $blob_name
                'Prefix' = $prefix
                'TargetList' = $target_list
            }
            $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
            $prefix = $null
            $blob_name = $null
            $target_list = $null
        }

        $servers = @()
        $object_list | ForEach-Object {
            if ($_.TargetList) {
                $_.TargetList | ForEach-Object {
                    $servers += $_.split("\")[2]
                }
            }
        }

        $servers
    }

    function Get-DFSshareV1 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)]
            [Int]
            $PageSize = 200,

            [Management.Automation.PSCredential]
            $Credential
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=fTDfs))"

            try {
                $Results = $DFSSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $RemoteNames = $Properties.remoteservername
                    $Pkt = $Properties.pkt

                    $DFSshares += $RemoteNames | ForEach-Object {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Verbose "Error in parsing DFS share : $_"
                        }
                    }
                }
                $Results.dispose()
                $DFSSearcher.dispose()

                if($pkt -and $pkt[0]) {
                    Parse-Pkt $pkt[0] | ForEach-Object {
                        # If a folder doesn't have a redirection it will
                        # have a target like
                        # \\null\TestNameSpace\folder\.DFSFolderLink so we
                        # do actually want to match on "null" rather than
                        # $null
                        if ($_ -ne "null") {
                            New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                        }
                    }
                }
            }
            catch {
                Write-Warning "Get-DFSshareV1 error : $_"
            }
            $DFSshares | Sort-Object -Property "RemoteServerName"
        }
    }

    function Get-DFSshareV2 {
        [CmdletBinding()]
        param(
            [String]
            $Domain,

            [String]
            $DomainController,

            [String]
            $ADSpath,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200,

            [Management.Automation.PSCredential]
            $Credential
        )

        $DFSsearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize

        if($DFSsearcher) {
            $DFSshares = @()
            $DFSsearcher.filter = "(&(objectClass=msDFS-Linkv2))"
            $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

            try {
                $Results = $DFSSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Properties = $_.Properties
                    $target_list = $Properties.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                    $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $Target = $_.InnerText
                            if ( $Target.Contains('\') ) {
                                $DFSroot = $Target.split("\")[3]
                                $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Verbose "Error in parsing target : $_"
                        }
                    }
                }
                $Results.dispose()
                $DFSSearcher.dispose()
            }
            catch {
                Write-Warning "Get-DFSshareV2 error : $_"
            }
            $DFSshares | Sort-Object -Unique -Property "RemoteServerName"
        }
    }

    $DFSshares = @()

    if ( ($Version -eq "all") -or ($Version.endsWith("1")) ) {
        $DFSshares += Get-DFSshareV1 -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }
    if ( ($Version -eq "all") -or ($Version.endsWith("2")) ) {
        $DFSshares += Get-DFSshareV2 -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    $DFSshares | Sort-Object -Property ("RemoteServerName","Name") -Unique
}

filter Get-GptTmpl {

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,

        [Switch]
        $UsePSDrive
    )

    if($UsePSDrive) {
        # if we're PSDrives, create a temporary mount point
        $Parts = $GptTmplPath.split('\')
        $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
        $FilePath = $Parts[-1]
        $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''

        Write-Verbose "Mounting path $GptTmplPath using a temp PSDrive at $RandDrive"

        try {
            $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
        }
        catch {
            Write-Verbose "Error mounting path $GptTmplPath : $_"
            return $Null
        }

        # so we can cd/dir the new drive
        $TargetGptTmplPath = $RandDrive + ":\" + $FilePath
    }
    else {
        $TargetGptTmplPath = $GptTmplPath
    }

    Write-Verbose "GptTmplPath: $GptTmplPath"

    try {
        Write-Verbose "Parsing $TargetGptTmplPath"
        $TargetGptTmplPath | Get-IniContent -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Error parsing $TargetGptTmplPath : $_"
    }

    if($UsePSDrive -and $RandDrive) {
        Write-Verbose "Removing temp PSDrive $RandDrive"
        Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
    }
}

filter Get-GroupsXML {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,

        [Switch]
        $UsePSDrive
    )

    if($UsePSDrive) {
        # if we're PSDrives, create a temporary mount point
        $Parts = $GroupsXMLPath.split('\')
        $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
        $FilePath = $Parts[-1]
        $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''

        Write-Verbose "Mounting path $GroupsXMLPath using a temp PSDrive at $RandDrive"

        try {
            $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
        }
        catch {
            Write-Verbose "Error mounting path $GroupsXMLPath : $_"
            return $Null
        }

        # so we can cd/dir the new drive
        $TargetGroupsXMLPath = $RandDrive + ":\" + $FilePath
    }
    else {
        $TargetGroupsXMLPath = $GroupsXMLPath
    }

    try {
        [XML]$GroupsXMLcontent = Get-Content $TargetGroupsXMLPath -ErrorAction Stop

        # process all group properties in the XML
        $GroupsXMLcontent | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {

            $Groupname = $_.Properties.groupName

            # extract the localgroup sid for memberof
            $GroupSID = $_.Properties.groupSid
            if(-not $GroupSID) {
                if($Groupname -match 'Administrators') {
                    $GroupSID = 'S-1-5-32-544'
                }
                elseif($Groupname -match 'Remote Desktop') {
                    $GroupSID = 'S-1-5-32-555'
                }
                elseif($Groupname -match 'Guests') {
                    $GroupSID = 'S-1-5-32-546'
                }
                else {
                    $GroupSID = Convert-NameToSid -ObjectName $Groupname | Select-Object -ExpandProperty SID
                }
            }

            # extract out members added to this group
            $Members = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                if($_.sid) { $_.sid }
                else { $_.name }
            }

            if ($Members) {

                # extract out any/all filters...I hate you GPP
                if($_.filters) {
                    $Filters = $_.filters.GetEnumerator() | ForEach-Object {
                        New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                    }
                }
                else {
                    $Filters = $Null
                }

                if($Members -isnot [System.Array]) { $Members = @($Members) }

                $GPOGroup = New-Object PSObject
                $GPOGroup | Add-Member Noteproperty 'GPOPath' $TargetGroupsXMLPath
                $GPOGroup | Add-Member Noteproperty 'Filters' $Filters
                $GPOGroup | Add-Member Noteproperty 'GroupName' $GroupName
                $GPOGroup | Add-Member Noteproperty 'GroupSID' $GroupSID
                $GPOGroup | Add-Member Noteproperty 'GroupMemberOf' $Null
                $GPOGroup | Add-Member Noteproperty 'GroupMembers' $Members
                $GPOGroup
            }
        }
    }
    catch {
        Write-Verbose "Error parsing $TargetGroupsXMLPath : $_"
    }

    if($UsePSDrive -and $RandDrive) {
        Write-Verbose "Removing temp PSDrive $RandDrive"
        Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
    }
}

function Get-ThisThingGPO {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [String]
        $ComputerName,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if ($GPOSearcher) {

            if($ComputerName) {
                $GPONames = @()
                $Computers = Get-ThisThingComputer -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize

                if(!$Computers) {
                    throw "Computer $ComputerName in domain '$Domain' not found! Try a fully qualified host name"
                }
                
                # get the given computer's OU
                $ComputerOUs = @()
                ForEach($Computer in $Computers) {
                    # extract all OUs a computer is a part of
                    $DN = $Computer.distinguishedname

                    $ComputerOUs += $DN.split(",") | ForEach-Object {
                        if($_.startswith("OU=")) {
                            $DN.substring($DN.indexof($_))
                        }
                    }
                }
                
                Write-Verbose "ComputerOUs: $ComputerOUs"

                # find all the GPOs linked to the computer's OU
                ForEach($ComputerOU in $ComputerOUs) {
                    $GPONames += Get-ThisThingOU -Domain $Domain -DomainController $DomainController -ADSpath $ComputerOU -FullData -PageSize $PageSize | ForEach-Object { 
                        # get any GPO links
                        write-verbose "blah: $($_.name)"
                        $_.gplink.split("][") | ForEach-Object {
                            if ($_.startswith("LDAP")) {
                                $_.split(";")[0]
                            }
                        }
                    }
                }
                
                Write-Verbose "GPONames: $GPONames"

                # find any GPOs linked to the site for the given computer
                $ComputerSite = (Get-SiteName -ComputerName $ComputerName).SiteName
                if($ComputerSite -and ($ComputerSite -notlike 'Error*')) {
                    $GPONames += Get-ThisThingSite -SiteName $ComputerSite -FullData | ForEach-Object {
                        if($_.gplink) {
                            $_.gplink.split("][") | ForEach-Object {
                                if ($_.startswith("LDAP")) {
                                    $_.split(";")[0]
                                }
                            }
                        }
                    }
                }

                $GPONames | Where-Object{$_ -and ($_ -ne '')} | ForEach-Object {

                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $_ -PageSize $PageSize
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=$GPOname))"

                    try {
                        $Results = $GPOSearcher.FindAll()
                        $Results | Where-Object {$_} | ForEach-Object {
                            $Out = Convert-LDAPProperty -Properties $_.Properties
                            $Out | Add-Member Noteproperty 'ComputerName' $ComputerName
                            $Out
                        }
                        $Results.dispose()
                        $GPOSearcher.dispose()
                    }
                    catch {
                        Write-Warning $_
                    }
                }
            }

            else {
                if($DisplayName) {
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(displayname=$DisplayName))"
                }
                else {
                    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=$GPOname))"
                }

                try {
                    $Results = $GPOSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        if($ADSPath -and ($ADSpath -Match '^GC://')) {
                            $Properties = Convert-LDAPProperty -Properties $_.Properties
                            try {
                                $GPODN = $Properties.distinguishedname
                                $GPODomain = $GPODN.subString($GPODN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                                $gpcfilesyspath = "\\$GPODomain\SysVol\$GPODomain\Policies\$($Properties.cn)"
                                $Properties | Add-Member Noteproperty 'gpcfilesyspath' $gpcfilesyspath
                                $Properties
                            }
                            catch {
                                $Properties
                            }
                        }
                        else {
                            # convert/process the LDAP fields for each result
                            Convert-LDAPProperty -Properties $_.Properties
                        }
                    }
                    $Results.dispose()
                    $GPOSearcher.dispose()
                }
                catch {
                    Write-Warning $_
                }
            }
        }
    }
}

function New-GPOImmediateTask {
    [CmdletBinding(DefaultParameterSetName = 'Create')]
    Param (
        [Parameter(ParameterSetName = 'Create', Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskName,

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Command = 'powershell',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $CommandArguments,

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskDescription = '',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskAuthor = 'NT AUTHORITY\System',

        [Parameter(ParameterSetName = 'Create')]
        [String]
        [ValidateNotNullOrEmpty()]
        $TaskModifiedDate = (Get-Date (Get-Date).AddDays(-30) -Format u).trim("Z"),

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $GPOname,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $GPODisplayName,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $Domain,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $DomainController,
        
        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [String]
        $ADSpath,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]
        [Switch]
        $Force,

        [Parameter(ParameterSetName = 'Remove')]
        [Switch]
        $Remove,

        [Parameter(ParameterSetName = 'Create')]
        [Parameter(ParameterSetName = 'Remove')]        
        [Management.Automation.PSCredential]
        $Credential
    )

    # build the XML spec for our 'immediate' scheduled task
    $TaskXML = '<?xml version="1.0" encoding="utf-8"?><ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}"><ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="'+$TaskName+'" image="0" changed="'+$TaskModifiedDate+'" uid="{'+$([guid]::NewGuid())+'}" userContext="0" removePolicy="0"><Properties action="C" name="'+$TaskName+'" runAs="NT AUTHORITY\System" logonType="S4U"><Task version="1.3"><RegistrationInfo><Author>'+$TaskAuthor+'</Author><Description>'+$TaskDescription+'</Description></RegistrationInfo><Principals><Principal id="Author"><UserId>NT AUTHORITY\System</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>S4U</LogonType></Principal></Principals><Settings><IdleSettings><Duration>PT10M</Duration><WaitTimeout>PT1H</WaitTimeout><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>true</StopIfGoingOnBatteries><AllowHardTerminate>false</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>false</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>7</Priority><DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter><RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context="Author"><Exec><Command>'+$Command+'</Command><Arguments>'+$CommandArguments+'</Arguments></Exec></Actions><Triggers><TimeTrigger><StartBoundary>%LocalTimeXmlEx%</StartBoundary><EndBoundary>%LocalTimeXmlEx%</EndBoundary><Enabled>true</Enabled></TimeTrigger></Triggers></Task></Properties></ImmediateTaskV2></ScheduledTasks>'

    if (!$PSBoundParameters['GPOname'] -and !$PSBoundParameters['GPODisplayName']) {
        Write-Warning 'Either -GPOName or -GPODisplayName must be specified'
        return
    }

    # eunmerate the specified GPO(s)
    $GPOs = Get-ThisThingGPO -GPOname $GPOname -DisplayName $GPODisplayName -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -Credential $Credential 
    
    if(!$GPOs) {
        Write-Warning 'No GPO found.'
        return
    }

    $GPOs | ForEach-Object {
        $ProcessedGPOName = $_.Name
        try {
            Write-Verbose "Trying to weaponize GPO: $ProcessedGPOName"

            # map a network drive as New-PSDrive/New-Item/etc. don't accept -Credential properly :(
            if($Credential) {
                Write-Verbose "Mapping '$($_.gpcfilesyspath)' to network drive N:\"
                $Path = $_.gpcfilesyspath.TrimEnd('\')
                $Net = New-Object -ComObject WScript.Network
                $Net.MapNetworkDrive("N:", $Path, $False, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                $TaskPath = "N:\Machine\Preferences\ScheduledTasks\"
            }
            else {
                $TaskPath = $_.gpcfilesyspath + "\Machine\Preferences\ScheduledTasks\"
            }

            if($Remove) {
                if(!(Test-Path "$TaskPath\ScheduledTasks.xml")) {
                    Throw "Scheduled task doesn't exist at $TaskPath\ScheduledTasks.xml"
                }

                if (!$Force -and !$psCmdlet.ShouldContinue('Do you want to continue?',"Removing schtask at $TaskPath\ScheduledTasks.xml")) {
                    return
                }

                Remove-Item -Path "$TaskPath\ScheduledTasks.xml" -Force
            }
            else {
                if (!$Force -and !$psCmdlet.ShouldContinue('Do you want to continue?',"Creating schtask at $TaskPath\ScheduledTasks.xml")) {
                    return
                }
                
                # create the folder if it doesn't exist
                $Null = New-Item -ItemType Directory -Force -Path $TaskPath

                if(Test-Path "$TaskPath\ScheduledTasks.xml") {
                    Throw "Scheduled task already exists at $TaskPath\ScheduledTasks.xml !"
                }

                $TaskXML | Set-Content -Encoding ASCII -Path "$TaskPath\ScheduledTasks.xml"
            }

            if($Credential) {
                Write-Verbose "Removing mounted drive at N:\"
                $Net = New-Object -ComObject WScript.Network
                $Net.RemoveNetworkDrive("N:")
            }
        }
        catch {
            Write-Warning "Error for GPO $ProcessedGPOName : $_"
            if($Credential) {
                Write-Verbose "Removing mounted drive at N:\"
                $Net = New-Object -ComObject WScript.Network
                $Net.RemoveNetworkDrive("N:")
            }
        }
    }
}

function Get-ThisThingGPOGroup {
    [CmdletBinding()]
    Param (
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $ResolveMemberSIDs,

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Option = [System.StringSplitOptions]::RemoveEmptyEntries

    # get every GPO from the specified domain with restricted groups set
    Get-ThisThingGPO -GPOName $GPOname -DisplayName $DisplayName -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize | ForEach-Object {

        $GPOdisplayName = $_.displayname
        $GPOname = $_.name
        $GPOPath = $_.gpcfilesyspath

        $ParseArgs =  @{
            'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = $UsePSDrive
        }

        # parse the GptTmpl.inf 'Restricted Groups' file if it exists
        $Inf = Get-GptTmpl @ParseArgs

        if($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {

            $Memberships = @{}

            # group the members/memberof fields for each entry
            ForEach ($Membership in $Inf.'Group Membership'.GetEnumerator()) {
                $Group, $Relation = $Membership.Key.Split('__', $Option) | ForEach-Object {$_.Trim()}

                # extract out ALL members
                $MembershipValue = $Membership.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}

                if($ResolveMemberSIDs) {
                    # if the resulting member is username and not a SID, attempt to resolve it
                    $GroupMembers = @()
                    ForEach($Member in $MembershipValue) {
                        if($Member -and ($Member.Trim() -ne '')) {
                            if($Member -notmatch '^S-1-.*') {
                                $MemberSID = Convert-NameToSid -Domain $Domain -ObjectName $Member | Select-Object -ExpandProperty SID
                                if($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $MembershipValue = $GroupMembers
                }

                if(-not $Memberships[$Group]) {
                    $Memberships[$Group] = @{}
                }
                if($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                $Memberships[$Group].Add($Relation, $MembershipValue)
            }

            ForEach ($Membership in $Memberships.GetEnumerator()) {
                if($Membership -and $Membership.Key -and ($Membership.Key -match '^\*')) {
                    # if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                    $GroupSID = $Membership.Key.Trim('*')
                    if($GroupSID -and ($GroupSID.Trim() -ne '')) {
                        $GroupName = Convert-SidToName -SID $GroupSID
                    }
                    else {
                        $GroupName = $False
                    }
                }
                else {
                    $GroupName = $Membership.Key

                    if($GroupName -and ($GroupName.Trim() -ne '')) {
                        if($Groupname -match 'Administrators') {
                            $GroupSID = 'S-1-5-32-544'
                        }
                        elseif($Groupname -match 'Remote Desktop') {
                            $GroupSID = 'S-1-5-32-555'
                        }
                        elseif($Groupname -match 'Guests') {
                            $GroupSID = 'S-1-5-32-546'
                        }
                        elseif($GroupName.Trim() -ne '') {
                            $GroupSID = Convert-NameToSid -Domain $Domain -ObjectName $Groupname | Select-Object -ExpandProperty SID
                        }
                        else {
                            $GroupSID = $Null
                        }
                    }
                }

                $GPOGroup = New-Object PSObject
                $GPOGroup | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
                $GPOGroup | Add-Member Noteproperty 'GPOName' $GPOName
                $GPOGroup | Add-Member Noteproperty 'GPOPath' $GPOPath
                $GPOGroup | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                $GPOGroup | Add-Member Noteproperty 'Filters' $Null
                $GPOGroup | Add-Member Noteproperty 'GroupName' $GroupName
                $GPOGroup | Add-Member Noteproperty 'GroupSID' $GroupSID
                $GPOGroup | Add-Member Noteproperty 'GroupMemberOf' $Membership.Value.Memberof
                $GPOGroup | Add-Member Noteproperty 'GroupMembers' $Membership.Value.Members
                $GPOGroup
            }
        }

        $ParseArgs =  @{
            'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            'UsePSDrive' = $UsePSDrive
        }

        Get-GroupsXML @ParseArgs | ForEach-Object {
            if($ResolveMemberSIDs) {
                $GroupMembers = @()
                ForEach($Member in $_.GroupMembers) {
                    if($Member -and ($Member.Trim() -ne '')) {
                        if($Member -notmatch '^S-1-.*') {
                            # if the resulting member is username and not a SID, attempt to resolve it
                            $MemberSID = Convert-NameToSid -Domain $Domain -ObjectName $Member | Select-Object -ExpandProperty SID
                            if($MemberSID) {
                                $GroupMembers += $MemberSID
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                        else {
                            $GroupMembers += $Member
                        }
                    }
                }
                $_.GroupMembers = $GroupMembers
            }

            $_ | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
            $_ | Add-Member Noteproperty 'GPOName' $GPOName
            $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
            $_
        }
    }
}

function Find-GPOLocation {
    [CmdletBinding()]
    Param (
        [String]
        $UserName,

        [String]
        $GroupName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $LocalGroup = 'Administrators',
        
        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if($UserName) {
        # if a group name is specified, get that user object so we can extract the target SID
        $User = Get-ThisThingUser -UserName $UserName -Domain $Domain -DomainController $DomainController -PageSize $PageSize | Select-Object -First 1
        $UserSid = $User.objectsid

        if(-not $UserSid) {    
            Throw "User '$UserName' not found!"
        }

        $TargetSIDs = @($UserSid)
        $ObjectSamAccountName = $User.samaccountname
        $TargetObject = $UserSid
    }
    elseif($GroupName) {
        # if a group name is specified, get that group object so we can extract the target SID
        $Group = Get-ThisThingGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Select-Object -First 1
        $GroupSid = $Group.objectsid

        if(-not $GroupSid) {    
            Throw "Group '$GroupName' not found!"
        }

        $TargetSIDs = @($GroupSid)
        $ObjectSamAccountName = $Group.samaccountname
        $TargetObject = $GroupSid
    }
    else {
        $TargetSIDs = @('*')
    }

    # figure out what the SID is of the target local group we're checking for membership in
    if($LocalGroup -like "*Admin*") {
        $TargetLocalSID = 'S-1-5-32-544'
    }
    elseif ( ($LocalGroup -like "*RDP*") -or ($LocalGroup -like "*Remote*") ) {
        $TargetLocalSID = 'S-1-5-32-555'
    }
    elseif ($LocalGroup -like "S-1-5-*") {
        $TargetLocalSID = $LocalGroup
    }
    else {
        throw "LocalGroup must be 'Administrators', 'RDP', or a 'S-1-5-X' SID format."
    }

    # if we're not listing all relationships, use the tokenGroups approach from Get-ThisThingGroup to 
    # get all effective security SIDs this object is a part of
    if($TargetSIDs[0] -and ($TargetSIDs[0] -ne '*')) {
        $TargetSIDs += Get-ThisThingGroup -Domain $Domain -DomainController $DomainController -PageSize $PageSize -UserName $ObjectSamAccountName -RawSids
    }

    if(-not $TargetSIDs) {
        throw "No effective target SIDs!"
    }

    Write-Verbose "TargetLocalSID: $TargetLocalSID"
    Write-Verbose "Effective target SIDs: $TargetSIDs"

    $GPOGroupArgs =  @{
        'Domain' = $Domain
        'DomainController' = $DomainController
        'UsePSDrive' = $UsePSDrive
        'ResolveMemberSIDs' = $True
        'PageSize' = $PageSize
    }

    # enumerate all GPO group mappings for the target domain that involve our target SID set
    $GPOgroups = Get-ThisThingGPOGroup @GPOGroupArgs | ForEach-Object {

        $GPOgroup = $_

        # if the locally set group is what we're looking for, check the GroupMembers ('members')
        #    for our target SID
        if($GPOgroup.GroupSID -match $TargetLocalSID) {
            $GPOgroup.GroupMembers | Where-Object {$_} | ForEach-Object {
                if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $_) ) {
                    $GPOgroup
                }
            }
        }
        # if the group is a 'memberof' the group we're looking for, check GroupSID against the targt SIDs 
        if( ($GPOgroup.GroupMemberOf -contains $TargetLocalSID) ) {
            if( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $GPOgroup.GroupSID) ) {
                $GPOgroup
            }
        }
    } | Sort-Object -Property GPOName -Unique

    $GPOgroups | ForEach-Object {

        $GPOname = $_.GPODisplayName
        $GPOguid = $_.GPOName
        $GPOPath = $_.GPOPath
        $GPOType = $_.GPOType
        if($_.GroupMembers) {
            $GPOMembers = $_.GroupMembers
        }
        else {
            $GPOMembers = $_.GroupSID
        }
        
        $Filters = $_.Filters

        if(-not $TargetObject) {
            # if the * wildcard was used, set the ObjectDistName as the GPO member SID set
            #   so all relationship mappings are output
            $TargetObjectSIDs = $GPOMembers
        }
        else {
            $TargetObjectSIDs = $TargetObject
        }

        # find any OUs that have this GUID applied and then retrieve any computers from the OU
        Get-ThisThingOU -Domain $Domain -DomainController $DomainController -GUID $GPOguid -FullData -PageSize $PageSize | ForEach-Object {
            if($Filters) {
                # filter for computer name/org unit if a filter is specified
                #   TODO: handle other filters (i.e. OU filters?) again, I hate you GPP...
                $OUComputers = Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $_.ADSpath -FullData -PageSize $PageSize | Where-Object {
                    $_.adspath -match ($Filters.Value)
                } | ForEach-Object { $_.dnshostname }
            }
            else {
                $OUComputers = Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $_.ADSpath -PageSize $PageSize
            }

            if($OUComputers) {
                if($OUComputers -isnot [System.Array]) {$OUComputers = @($OUComputers)}

                ForEach ($TargetSid in $TargetObjectSIDs) {
                    $Object = Get-ADObject -SID $TargetSid -Domain $Domain -DomainController $DomainController -Credential $Credential -PageSize $PageSize

                    $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                    $GPOLocation = New-Object PSObject
                    $GPOLocation | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                    $GPOLocation | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $GPOLocation | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                    $GPOLocation | Add-Member Noteproperty 'Domain' $Domain
                    $GPOLocation | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GPOLocation | Add-Member Noteproperty 'GPODisplayName' $GPOname
                    $GPOLocation | Add-Member Noteproperty 'GPOGuid' $GPOGuid
                    $GPOLocation | Add-Member Noteproperty 'GPOPath' $GPOPath
                    $GPOLocation | Add-Member Noteproperty 'GPOType' $GPOType
                    $GPOLocation | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $GPOLocation | Add-Member Noteproperty 'ComputerName' $OUComputers
                    $GPOLocation.PSObject.TypeNames.Add('PowerView.GPOLocalGroup')
                    $GPOLocation
                }
            }
        }

        # find any sites that have this GUID applied
        Get-ThisThingSite -Domain $Domain -DomainController $DomainController -GUID $GPOguid -PageSize $PageSize -FullData | ForEach-Object {

            ForEach ($TargetSid in $TargetObjectSIDs) {
                $Object = Get-ADObject -SID $TargetSid -Domain $Domain -DomainController $DomainController -Credential $Credential -PageSize $PageSize

                $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                $AppliedSite = New-Object PSObject
                $AppliedSite | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                $AppliedSite | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                $AppliedSite | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                $AppliedSite | Add-Member Noteproperty 'IsGroup' $IsGroup
                $AppliedSite | Add-Member Noteproperty 'Domain' $Domain
                $AppliedSite | Add-Member Noteproperty 'GPODisplayName' $GPOname
                $AppliedSite | Add-Member Noteproperty 'GPOGuid' $GPOGuid
                $AppliedSite | Add-Member Noteproperty 'GPOPath' $GPOPath
                $AppliedSite | Add-Member Noteproperty 'GPOType' $GPOType
                $AppliedSite | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                $AppliedSite | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                $AppliedSite.PSObject.TypeNames.Add('PowerView.GPOLocalGroup')
                $AppliedSite
            }
        }
    }
}

function Find-GPOComputerAdmin {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ComputerName,

        [String]
        $OUName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $Recurse,

        [String]
        $LocalGroup = 'Administrators',

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    process {
    
        if(!$ComputerName -and !$OUName) {
            Throw "-ComputerName or -OUName must be provided"
        }

        $GPOGroups = @()

        if($ComputerName) {
            $Computers = Get-ThisThingComputer -ComputerName $ComputerName -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize

            if(!$Computers) {
                throw "Computer $ComputerName in domain '$Domain' not found! Try a fully qualified host name"
            }
            
            $TargetOUs = @()
            ForEach($Computer in $Computers) {
                # extract all OUs a computer is a part of
                $DN = $Computer.distinguishedname

                $TargetOUs += $DN.split(",") | ForEach-Object {
                    if($_.startswith("OU=")) {
                        $DN.substring($DN.indexof($_))
                    }
                }
            }

            # enumerate any linked GPOs for the computer's site
            $ComputerSite = (Get-SiteName -ComputerName $ComputerName).SiteName
            if($ComputerSite -and ($ComputerSite -notlike 'Error*')) {
                $GPOGroups += Get-ThisThingSite -SiteName $ComputerSite -FullData | ForEach-Object {
                    if($_.gplink) {
                        $_.gplink.split("][") | ForEach-Object {
                            if ($_.startswith("LDAP")) {
                                $_.split(";")[0]
                            }
                        }
                    }
                } | ForEach-Object {
                    $GPOGroupArgs =  @{
                        'Domain' = $Domain
                        'DomainController' = $DomainController
                        'ResolveMemberSIDs' = $True
                        'UsePSDrive' = $UsePSDrive
                        'PageSize' = $PageSize
                    }

                    # for each GPO link, get any locally set user/group SIDs
                    Get-ThisThingGPOGroup @GPOGroupArgs
                }
            }
        }
        else {
            $TargetOUs = @($OUName)
        }

        Write-Verbose "Target OUs: $TargetOUs"

        $TargetOUs | Where-Object {$_} | ForEach-Object {

            $GPOLinks = Get-ThisThingOU -Domain $Domain -DomainController $DomainController -ADSpath $_ -FullData -PageSize $PageSize | ForEach-Object { 
                # and then get any GPO links
                if($_.gplink) {
                    $_.gplink.split("][") | ForEach-Object {
                        if ($_.startswith("LDAP")) {
                            $_.split(";")[0]
                        }
                    }
                }
            }

            $GPOGroupArgs =  @{
                'Domain' = $Domain
                'DomainController' = $DomainController
                'UsePSDrive' = $UsePSDrive
                'ResolveMemberSIDs' = $True
                'PageSize' = $PageSize
            }

            # extract GPO groups that are set through any gPlink for this OU
            $GPOGroups += Get-ThisThingGPOGroup @GPOGroupArgs | ForEach-Object {
                ForEach($GPOLink in $GPOLinks) {
                    $Name = $_.GPOName
                    if($GPOLink -like "*$Name*") {
                        $_
                    }
                }
            }
        }

        # for each found GPO group, resolve the SIDs of the members
        $GPOgroups | Sort-Object -Property GPOName -Unique | ForEach-Object {
            $GPOGroup = $_

            if($GPOGroup.GroupMembers) {
                $GPOMembers = $GPOGroup.GroupMembers
            }
            else {
                $GPOMembers = $GPOGroup.GroupSID
            }

            $GPOMembers | ForEach-Object {
                # resolve this SID to a domain object
                $Object = Get-ADObject -Domain $Domain -DomainController $DomainController -PageSize $PageSize -SID $_

                $IsGroup = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype

                $GPOComputerAdmin = New-Object PSObject
                $GPOComputerAdmin | Add-Member Noteproperty 'ComputerName' $ComputerName
                $GPOComputerAdmin | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                $GPOComputerAdmin | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                $GPOComputerAdmin | Add-Member Noteproperty 'ObjectSID' $_
                $GPOComputerAdmin | Add-Member Noteproperty 'IsGroup' $IsGroup
                $GPOComputerAdmin | Add-Member Noteproperty 'GPODisplayName' $GPOGroup.GPODisplayName
                $GPOComputerAdmin | Add-Member Noteproperty 'GPOGuid' $GPOGroup.GPOName
                $GPOComputerAdmin | Add-Member Noteproperty 'GPOPath' $GPOGroup.GPOPath
                $GPOComputerAdmin | Add-Member Noteproperty 'GPOType' $GPOGroup.GPOType
                $GPOComputerAdmin

                # if we're recursing and the current result object is a group
                if($Recurse -and $GPOComputerAdmin.isGroup) {

                    Get-ThisThingGroupMember -Domain $Domain -DomainController $DomainController -SID $_ -FullData -Recurse -PageSize $PageSize | ForEach-Object {

                        $MemberDN = $_.distinguishedName

                        # extract the FQDN from the Distinguished Name
                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                        $MemberIsGroup = @('268435456','268435457','536870912','536870913') -contains $_.samaccounttype

                        if ($_.samAccountName) {
                            # forest users have the samAccountName set
                            $MemberName = $_.samAccountName
                        }
                        else {
                            # external trust users have a SID, so convert it
                            try {
                                $MemberName = Convert-SidToName $_.cn
                            }
                            catch {
                                # if there's a problem contacting the domain to resolve the SID
                                $MemberName = $_.cn
                            }
                        }

                        $GPOComputerAdmin = New-Object PSObject
                        $GPOComputerAdmin | Add-Member Noteproperty 'ComputerName' $ComputerName
                        $GPOComputerAdmin | Add-Member Noteproperty 'ObjectName' $MemberName
                        $GPOComputerAdmin | Add-Member Noteproperty 'ObjectDN' $MemberDN
                        $GPOComputerAdmin | Add-Member Noteproperty 'ObjectSID' $_.objectsid
                        $GPOComputerAdmin | Add-Member Noteproperty 'IsGroup' $MemberIsGrou
                        $GPOComputerAdmin | Add-Member Noteproperty 'GPODisplayName' $GPOGroup.GPODisplayName
                        $GPOComputerAdmin | Add-Member Noteproperty 'GPOGuid' $GPOGroup.GPOName
                        $GPOComputerAdmin | Add-Member Noteproperty 'GPOPath' $GPOGroup.GPOPath
                        $GPOComputerAdmin | Add-Member Noteproperty 'GPOType' $GPOTypep
                        $GPOComputerAdmin 
                    }
                }
            }
        }
    }
}

function Get-DomainPolicy {
    [CmdletBinding()]
    Param (
        [String]
        [ValidateSet("Domain","DC")]
        $Source ="Domain",

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $ResolveSids,

        [Switch]
        $UsePSDrive
    )

    if($Source -eq "Domain") {
        # query the given domain for the default domain policy object
        $GPO = Get-ThisThingGPO -Domain $Domain -DomainController $DomainController -GPOname "{31B2F340-016D-11D2-945F-00C04FB984F9}"
        
        if($GPO) {
            # grab the GptTmpl.inf file and parse it
            $GptTmplPath = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }

            # parse the GptTmpl.inf
            Get-GptTmpl @ParseArgs
        }

    }
    elseif($Source -eq "DC") {
        # query the given domain/dc for the default domain controller policy object
        $GPO = Get-ThisThingGPO -Domain $Domain -DomainController $DomainController -GPOname "{6AC1786C-016F-11D2-945F-00C04FB984F9}"

        if($GPO) {
            # grab the GptTmpl.inf file and parse it
            $GptTmplPath = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'UsePSDrive' = $UsePSDrive
            }

            # parse the GptTmpl.inf
            Get-GptTmpl @ParseArgs | ForEach-Object {
                if($ResolveSids) {
                    # if we're resolving sids in PrivilegeRights to names
                    $Policy = New-Object PSObject
                    $_.psobject.properties | ForEach-Object {
                        if( $_.Name -eq 'PrivilegeRights') {

                            $PrivilegeRights = New-Object PSObject
                            # for every nested SID member of PrivilegeRights, try to unpack everything and resolve the SIDs as appropriate
                            $_.Value.psobject.properties | ForEach-Object {

                                $Sids = $_.Value | ForEach-Object {
                                    try {
                                        if($_ -isnot [System.Array]) { 
                                            Convert-SidToName $_ 
                                        }
                                        else {
                                            $_ | ForEach-Object { Convert-SidToName $_ }
                                        }
                                    }
                                    catch {
                                        Write-Verbose "Error resolving SID : $_"
                                    }
                                }

                                $PrivilegeRights | Add-Member Noteproperty $_.Name $Sids
                            }

                            $Policy | Add-Member Noteproperty 'PrivilegeRights' $PrivilegeRights
                        }
                        else {
                            $Policy | Add-Member Noteproperty $_.Name $_.Value
                        }
                    }
                    $Policy
                }
                else { $_ }
            }
        }
    }
}

function Get-ThisThingLocalGroup {
    [CmdletBinding(DefaultParameterSetName = 'WinNT')]
    param(
        [Parameter(ParameterSetName = 'API', Position=0, ValueFromPipeline=$True)]
        [Parameter(ParameterSetName = 'WinNT', Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String[]]
        $ComputerName = $Env:ComputerName,

        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [String]
        $GroupName = 'Administrators',

        [Parameter(ParameterSetName = 'WinNT')]
        [Switch]
        $ListGroups,

        [Parameter(ParameterSetName = 'WinNT')]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API
    )

    process {

        $Servers = @()

        # if we have a host list passed, grab it
        if($ComputerFile) {
            $Servers = Get-Content -Path $ComputerFile
        }
        else {
            # otherwise assume a single host name
            $Servers += $ComputerName | Get-NameField
        }

        # query the specified group using the WINNT provider, and
        # extract fields as appropriate from the results
        ForEach($Server in $Servers) {

            if($API) {
                # if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information
                # arguments for NetLocalGroupGetMembers
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                # get the local user information
                $Result = $Netapi32::NetLocalGroupGetMembers($Server, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                # Locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                $LocalUsers = @()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ""
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if($Result2 -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $LocalUser = New-Object PSObject
                            $LocalUser | Add-Member Noteproperty 'ComputerName' $Server
                            $LocalUser | Add-Member Noteproperty 'AccountName' $Info.lgrmi2_domainandname
                            $LocalUser | Add-Member Noteproperty 'SID' $SidString

                            $IsGroup = $($Info.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $LocalUser | Add-Member Noteproperty 'IsGroup' $IsGroup
                            $LocalUser.PSObject.TypeNames.Add('PowerView.LocalUserAPI')

                            $LocalUsers += $LocalUser
                        }
                    }

                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    # try to extract out the machine SID by using the -500 account as a reference
                    $MachineSid = $LocalUsers | Where-Object {$_.SID -like '*-500'}
                    $Parts = $MachineSid.SID.Split('-')
                    $MachineSid = $Parts[0..($Parts.Length -2)] -join '-'

                    $LocalUsers | ForEach-Object {
                        if($_.SID -match $MachineSid) {
                            $_ | Add-Member Noteproperty 'IsDomain' $False
                        }
                        else {
                            $_ | Add-Member Noteproperty 'IsDomain' $True
                        }
                    }
                    $LocalUsers
                }
                else {
                    Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }

            else {
                # otherwise we're using the WinNT service provider
                try {
                    if($ListGroups) {
                        # if we're listing the group names on a remote server
                        $Computer = [ADSI]"WinNT://$Server,computer"

                        $Computer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                            $Group = New-Object PSObject
                            $Group | Add-Member Noteproperty 'Server' $Server
                            $Group | Add-Member Noteproperty 'Group' ($_.name[0])
                            $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value)
                            $Group | Add-Member Noteproperty 'Description' ($_.Description[0])
                            $Group.PSObject.TypeNames.Add('PowerView.LocalGroup')
                            $Group
                        }
                    }
                    else {
                        # otherwise we're listing the group members
                        $Members = @($([ADSI]"WinNT://$Server/$GroupName,group").psbase.Invoke('Members'))

                        $Members | ForEach-Object {

                            $Member = New-Object PSObject
                            $Member | Add-Member Noteproperty 'ComputerName' $Server

                            $AdsPath = ($_.GetType().InvokeMember('Adspath', 'GetProperty', $Null, $_, $Null)).Replace('WinNT://', '')
                            $Class = $_.GetType().InvokeMember('Class', 'GetProperty', $Null, $_, $Null)

                            # try to translate the NT4 domain to a FQDN if possible
                            $Name = Convert-ADName -ObjectName $AdsPath -InputType 'NT4' -OutputType 'Canonical'
                            $IsGroup = $Class -eq "Group"

                            if($Name) {
                                $FQDN = $Name.split("/")[0]
                                $ObjName = $AdsPath.split("/")[-1]
                                $Name = "$FQDN/$ObjName"
                                $IsDomain = $True
                            }
                            else {
                                $ObjName = $AdsPath.split("/")[-1]
                                $Name = $AdsPath
                                $IsDomain = $False
                            }

                            $Member | Add-Member Noteproperty 'AccountName' $Name
                            $Member | Add-Member Noteproperty 'IsDomain' $IsDomain
                            $Member | Add-Member Noteproperty 'IsGroup' $IsGroup

                            if($IsDomain) {
                                # translate the binary sid to a string
                                $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember('ObjectSID', 'GetProperty', $Null, $_, $Null),0)).Value)
                                $Member | Add-Member Noteproperty 'Description' ""
                                $Member | Add-Member Noteproperty 'Disabled' ""

                                if($IsGroup) {
                                    $Member | Add-Member Noteproperty 'LastLogin' ""
                                }
                                else {
                                    try {
                                        $Member | Add-Member Noteproperty 'LastLogin' ( $_.GetType().InvokeMember('LastLogin', 'GetProperty', $Null, $_, $Null))
                                    }
                                    catch {
                                        $Member | Add-Member Noteproperty 'LastLogin' ""
                                    }
                                }
                                $Member | Add-Member Noteproperty 'PwdLastSet' ""
                                $Member | Add-Member Noteproperty 'PwdExpired' ""
                                $Member | Add-Member Noteproperty 'UserFlags' ""
                            }
                            else {
                                # repull this user object so we can ensure correct information
                                $LocalUser = $([ADSI] "WinNT://$AdsPath")

                                # translate the binary sid to a string
                                $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.objectSid.value,0)).Value)
                                $Member | Add-Member Noteproperty 'Description' ($LocalUser.Description[0])

                                if($IsGroup) {
                                    $Member | Add-Member Noteproperty 'PwdLastSet' ""
                                    $Member | Add-Member Noteproperty 'PwdExpired' ""
                                    $Member | Add-Member Noteproperty 'UserFlags' ""
                                    $Member | Add-Member Noteproperty 'Disabled' ""
                                    $Member | Add-Member Noteproperty 'LastLogin' ""
                                }
                                else {
                                    $Member | Add-Member Noteproperty 'PwdLastSet' ( (Get-Date).AddSeconds(-$LocalUser.PasswordAge[0]))
                                    $Member | Add-Member Noteproperty 'PwdExpired' ( $LocalUser.PasswordExpired[0] -eq '1')
                                    $Member | Add-Member Noteproperty 'UserFlags' ( $LocalUser.UserFlags[0] )
                                    # UAC flags of 0x2 mean the account is disabled
                                    $Member | Add-Member Noteproperty 'Disabled' $(($LocalUser.userFlags.value -band 2) -eq 2)
                                    try {
                                        $Member | Add-Member Noteproperty 'LastLogin' ( $LocalUser.LastLogin[0])
                                    }
                                    catch {
                                        $Member | Add-Member Noteproperty 'LastLogin' ""
                                    }
                                }
                            }
                            $Member.PSObject.TypeNames.Add('PowerView.LocalUser')
                            $Member

                            # if the result is a group domain object and we're recursing,
                            #   try to resolve all the group member results
                            if($Recurse -and $IsGroup) {
                                if($IsDomain) {
                                  $FQDN = $Name.split("/")[0]
                                  $GroupName = $Name.split("/")[1].trim()

                                  Get-ThisThingGroupMember -GroupName $GroupName -Domain $FQDN -FullData -Recurse | ForEach-Object {

                                      $Member = New-Object PSObject
                                      $Member | Add-Member Noteproperty 'ComputerName' "$FQDN/$($_.GroupName)"

                                      $MemberDN = $_.distinguishedName
                                      # extract the FQDN from the Distinguished Name
                                      $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'

                                      $MemberIsGroup = @('268435456','268435457','536870912','536870913') -contains $_.samaccounttype

                                      if ($_.samAccountName) {
                                          # forest users have the samAccountName set
                                          $MemberName = $_.samAccountName
                                      }
                                      else {
                                          try {
                                              # external trust users have a SID, so convert it
                                              try {
                                                  $MemberName = Convert-SidToName $_.cn
                                              }
                                              catch {
                                                  # if there's a problem contacting the domain to resolve the SID
                                                  $MemberName = $_.cn
                                              }
                                          }
                                          catch {
                                              Write-Debug "Error resolving SID : $_"
                                          }
                                      }

                                      $Member | Add-Member Noteproperty 'AccountName' "$MemberDomain/$MemberName"
                                      $Member | Add-Member Noteproperty 'SID' $_.objectsid
                                      $Member | Add-Member Noteproperty 'Description' $_.description
                                      $Member | Add-Member Noteproperty 'Disabled' $False
                                      $Member | Add-Member Noteproperty 'IsGroup' $MemberIsGroup
                                      $Member | Add-Member Noteproperty 'IsDomain' $True
                                      $Member | Add-Member Noteproperty 'LastLogin' ''
                                      $Member | Add-Member Noteproperty 'PwdLastSet' $_.pwdLastSet
                                      $Member | Add-Member Noteproperty 'PwdExpired' ''
                                      $Member | Add-Member Noteproperty 'UserFlags' $_.userAccountControl
                                      $Member.PSObject.TypeNames.Add('PowerView.LocalUser')
                                      $Member
                                  }
                              } else {
                                Get-ThisThingLocalGroup -ComputerName $Server -GroupName $ObjName -Recurse
                              }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[!] Error: $_"
                }
            }
        }
    }
}

filter Get-MySMBShare {


    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost'
    )

    # extract the computer name from whatever object was passed on the pipeline
    $Computer = $ComputerName | Get-NameField

    # arguments for NetShareEnum
    $QueryLevel = 1
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get the share information
    $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # Work out how much to increment the pointer by finding out the size of the structure
        $Increment = $SHARE_INFO_1::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = $NewIntPtr -as $SHARE_INFO_1

            # return all the sections of the structure
            $Shares = $Info | Select-Object *
            $Shares | Add-Member Noteproperty 'ComputerName' $Computer
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            
            # Get ip address of host
            $targethostname = $Shares.ComputerName
            $ComputerIpAddress = [System.Net.Dns]::GetHostAddresses("$targethostname") | select IPAddressToString -first 1 -ExpandProperty IPAddressToString
            
            $ShareObject = New-Object -TypeName PSObject
            $ShareObject | Add-Member NoteProperty "ComputerName" $Shares.ComputerName
            $ShareObject | Add-Member NoteProperty "IpAddress" $ComputerIpAddress
            $ShareObject | Add-Member NoteProperty "ShareName" $Shares.shi1_netname 
            $ShareObject | Add-Member NoteProperty "ShareDesc" $Shares.shi1_remark
            $ShareObject | Add-Member NoteProperty "Sharetype" $Shares.shi1_type

            $ComputerName = $Shares.ComputerName  
            $ShareName = $Shares.shi1_netname 
            $ShareType = $Shares.shi1_type
            $ShareDesc = $Shares.shi1_remark  

            # Check access
            try{
                $TargetPath = "\\$ComputerName\$ShareName"
                $Null = [IO.Directory]::GetFiles($TargetPath)                                   
                Write-Verbose "$Computer : ACCESSIBLE! - Share: \\$computerName\$ShareName  Desc: $ShareDesc Type:$ShareType"
                $ShareObject | Add-Member NoteProperty "ShareAccess" "Yes"    
                $ShareObject 
            }catch{
                Write-Verbose "$Computer : NOT ACCESSIBLE - Share: \\$computerName\$ShareName Desc: $ShareDesc Type:$ShareType"                
                $ShareObject | Add-Member NoteProperty "ShareAccess" "No" 
                $ShareObject
            }
        }

        # free up the result buffer
        $Null = $Netapi32::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}

function Find-InterestingFile {
<#
    .SYNOPSIS

        This function recursively searches a given UNC path for files with
        specific keywords in the name (default of pass, sensitive, secret, admin,
        login and unattend*.xml). The output can be piped out to a csv with the
        -OutFile flag. By default, hidden files/folders are included in search results.

    .PARAMETER Path

        UNC/local path to recursively search.

    .PARAMETER Terms

        Terms to search for.

    .PARAMETER OfficeDocs

        Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

    .PARAMETER FreshEXEs

        Switch. Find .EXEs accessed within the last week.

    .PARAMETER LastAccessTime

        Only return files with a LastAccessTime greater than this date value.

    .PARAMETER LastWriteTime

        Only return files with a LastWriteTime greater than this date value.

    .PARAMETER CreationTime

        Only return files with a CreationTime greater than this date value.

    .PARAMETER ExcludeFolders

        Switch. Exclude folders from the search results.

    .PARAMETER ExcludeHidden

        Switch. Exclude hidden files and folders from the search results.

    .PARAMETER CheckWriteAccess

        Switch. Only returns files the current user has write access to.

    .PARAMETER OutFile

        Output results to a specified csv output file.

    .PARAMETER UsePSDrive

        Switch. Mount target remote path with temporary PSDrives.

    .OUTPUTS

        The full path, owner, lastaccess time, lastwrite time, and size for each found file.

    .EXAMPLE

        PS C:\> Find-InterestingFile -Path C:\Backup\
        
        Returns any files on the local path C:\Backup\ that have the default
        search term set in the title.

    .EXAMPLE

        PS C:\> Find-InterestingFile -Path \\WINDOWS7\Users\ -Terms salaries,email -OutFile out.csv
        
        Returns any files on the remote path \\WINDOWS7\Users\ that have 'salaries'
        or 'email' in the title, and writes the results out to a csv file
        named 'out.csv'

    .EXAMPLE

        PS C:\> Find-InterestingFile -Path \\WINDOWS7\Users\ -LastAccessTime (Get-Date).AddDays(-7)

        Returns any files on the remote path \\WINDOWS7\Users\ that have the default
        search term set in the title and were accessed within the last week.

    .LINK
        
        http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
#>
    
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Path = '.\',

        [Alias('Terms')]
        [String[]]
        $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential', '.config'),

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $UsePSDrive
    )

    begin {

        $Path += if(!$Path.EndsWith('\')) {"\"}

        if ($Credential) {
            $UsePSDrive = $True
        }

        # append wildcards to the front and back of all search terms
        $SearchTerms = $SearchTerms | ForEach-Object { if($_ -notmatch '^\*.*\*$') {"*$($_)*"} else{$_} }

        # search just for office documents if specified
        if ($OfficeDocs) {
            $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }

        # find .exe's accessed within the last 7 days
        if($FreshEXEs) {
            # get an access time limit of 7 days ago
            $LastAccessTime = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearchTerms = '*.exe'
        }

        if($UsePSDrive) {
            # if we're PSDrives, create a temporary mount point

            $Parts = $Path.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]

            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            
            Write-Verbose "Mounting path '$Path' using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath -ErrorAction Stop
            }
            catch {
                Write-Verbose "Error mounting path '$Path' : $_"
                return $Null
            }

            # so we can cd/dir the new drive
            $Path = "${RandDrive}:\${FilePath}"
        }
    }

    process {

        Write-Verbose "[*] Search path $Path"

        function Invoke-CheckWrite {
            # short helper to check is the current user can write to a file
            [CmdletBinding()]param([String]$Path)
            try {
                $Filetest = [IO.FILE]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                Write-Verbose -Message $Error[0]
                $False
            }
        }

        $SearchArgs =  @{
            'Path' = $Path
            'Recurse' = $True
            'Force' = $(-not $ExcludeHidden)
            'Include' = $SearchTerms
            'ErrorAction' = 'SilentlyContinue'
        }

        Get-ChildItem @SearchArgs | ForEach-Object {
            Write-Verbose $_
            # check if we're excluding folders
            if(!$ExcludeFolders -or !$_.PSIsContainer) {$_}
        } | ForEach-Object {
            if($LastAccessTime -or $LastWriteTime -or $CreationTime) {
                if($LastAccessTime -and ($_.LastAccessTime -gt $LastAccessTime)) {$_}
                elseif($LastWriteTime -and ($_.LastWriteTime -gt $LastWriteTime)) {$_}
                elseif($CreationTime -and ($_.CreationTime -gt $CreationTime)) {$_}
            }
            else {$_}
        } | ForEach-Object {
            # filter for write access (if applicable)
            if((-not $CheckWriteAccess) -or (Invoke-CheckWrite -Path $_.FullName)) {$_}
        } | Select-Object FullName,@{Name='Owner';Expression={(Get-Acl $_.FullName).Owner}},LastAccessTime,LastWriteTime,CreationTime,Length | ForEach-Object {
            # check if we're outputting to the pipeline or an output file
            if($OutFile) {Export-PowerViewCSV -InputObject $_ -OutFile $OutFile}
            else {$_}
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}


function Invoke-ThreadedFunction {
    # Helper used by any threaded host enumeration functions
    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$True)]
        [String[]]
        $ComputerName,

        [Parameter(Position=1,Mandatory=$True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,

        [Parameter(Position=2)]
        [Hashtable]
        $ScriptParameters,

        [Int]
        [ValidateRange(1,100)] 
        $Threads = 20,

        [Switch]
        $NoImports
    )

    begin {

        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"

        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if(!$NoImports) {

            # grab all the current variables for this runspace
            $MyVars = Get-Variable -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")

            # Add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach($Var in $MyVars) {
                if($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }

            # Add Functions from current runspace to the InitialSessionState
            ForEach($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()

        $method = $null
        ForEach ($m in [PowerShell].GetMethods() | Where-Object { $_.Name -eq "BeginInvoke" }) {
            $methodParameters = $m.GetParameters()
            if (($methodParameters.Count -eq 2) -and $methodParameters[0].Name -eq "input" -and $methodParameters[1].Name -eq "output") {
                $method = $m.MakeGenericMethod([Object], [Object])
                break
            }
        }

        $Jobs = @()
    }

    process {

        ForEach ($Computer in $ComputerName) {

            # make sure we get a server name
            if ($Computer -ne '') {
                # Write-Verbose "[*] Enumerating server $Computer ($($Counter+1) of $($ComputerName.count))"

                While ($($Pool.GetAvailableRunspaces()) -le 0) {
                    Start-Sleep -MilliSeconds 500
                }

                # create a "powershell pipeline runner"
                $p = [powershell]::create()

                $p.runspacepool = $Pool

                # add the script block + arguments
                $Null = $p.AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                if($ScriptParameters) {
                    ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                        $Null = $p.AddParameter($Param.Name, $Param.Value)
                    }
                }

                $o = New-Object Management.Automation.PSDataCollection[Object]

                $Jobs += @{
                    PS = $p
                    Output = $o
                    Result = $method.Invoke($p, @($null, [Management.Automation.PSDataCollection[Object]]$o))
                }
            }
        }
    }

    end {
        Write-Verbose "Waiting for threads to finish..."

        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
        } While (($Jobs | Where-Object { ! $_.Result.IsCompleted }).Count -gt 0)

        ForEach ($Job in $Jobs) {
            $Job.PS.Dispose()
        }

        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}



function Invoke-ShareFinder {

    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
 
        [Switch]
        $SearchForest,

        [ValidateRange(1,100)] 
        [Int]
        $Threads
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # random object for delay
        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running Invoke-ShareFinder with delay of $Delay"

        # figure out the shares we want to ignore
        [String[]] $ExcludedShares = @('')

        if ($ExcludePrint) {
            $ExcludedShares = $ExcludedShares + "PRINT$"
        }
        if ($ExcludeIPC) {
            $ExcludedShares = $ExcludedShares + "IPC$"
        }
        if ($ExcludeStandard) {
            $ExcludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
        }

        # if we're using a host file list, read the targets in and add them to the target list
        if($ComputerFile) {
            $ComputerName = Get-Content -Path $ComputerFile
        }

        if(!$ComputerName) { 
            [array]$ComputerName = @()

            if($Domain) {
                $TargetDomains = @($Domain)
            }
            elseif($SearchForest) {
                # get ALL the domains in the forest to search
                $TargetDomains = Get-ThisThingForestDomain | ForEach-Object { $_.Name }
            }
            else {
                # use the local domain
                $TargetDomains = @( (Get-ThisThingDomain).name )
            }
                
            ForEach ($Domain in $TargetDomains) {
                Write-Verbose "[*] Querying domain $Domain for hosts"
                $ComputerName += Get-ThisThingComputer -Domain $Domain -DomainController $DomainController -Filter $ComputerFilter -ADSpath $ComputerADSpath
            }
        
            # remove any null target hosts, uniquify the list and shuffle it
            $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
            if($($ComputerName.count) -eq 0) {
                throw "No hosts found!"
            }
        }

        # script block that enumerates a server
        $HostEnumBlock = {
            param($ComputerName, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

            # optionally check if the server is up first
            $Up = $True
            if($Ping) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
            }
            if($Up) {
                # get the shares for this host and check what we find
                $Shares = Get-MySMBShare -ComputerName $ComputerName
                ForEach ($Share in $Shares) {
                    Write-Verbose "[*] Server share: $Share"
                    $NetName = $Share.shi1_netname
                    $Remark = $Share.shi1_remark
                    $Path = '\\'+$ComputerName+'\'+$NetName

                    # make sure we get a real share name back
                    if (($NetName) -and ($NetName.trim() -ne '')) {
                        # if we're just checking for access to ADMIN$
                        if($CheckAdmin) {
                            if($NetName.ToUpper() -eq "ADMIN$") {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Verbose "Error accessing path $Path : $_"
                                }
                            }
                        }
                        # skip this share if it's in the exclude list
                        elseif ($ExcludedShares -NotContains $NetName.ToUpper()) {
                            # see if we want to check access to this share
                            if($CheckShareAccess) {
                                # check if the user has access to this path
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    "\\$ComputerName\$NetName `t- $Remark"
                                }
                                catch {
                                    Write-Verbose "Error accessing path $Path : $_"
                                }
                            }
                            else {
                                "\\$ComputerName\$NetName `t- $Remark"
                            }
                        }
                    }
                }
            }
        }

    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            # if we're using threading, kick off the script block with Invoke-ThreadedFunction
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'CheckShareAccess' = $CheckShareAccess
                'ExcludedShares' = $ExcludedShares
                'CheckAdmin' = $CheckAdmin
            }

            # kick off the threaded script block + arguments 
            Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }

        else {
            if(-not $NoPing -and ($ComputerName.count -ne 1)) {
                # ping all hosts in parallel
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            ForEach ($Computer in $ComputerName) {

                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $Computer ($Counter of $($ComputerName.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $Computer, $False, $CheckShareAccess, $ExcludedShares, $CheckAdmin
            }
        }
        
    }
}


function Invoke-FileFinder {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [Alias('Hosts')]
        [String[]]
        $ComputerName,

        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [String]
        $ComputerFilter,

        [String]
        $ComputerADSpath,

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $ShareList,

        [Switch]
        $OfficeDocs,

        [Switch]
        $FreshEXEs,

        [Alias('Terms')]
        [String[]]
        $SearchTerms, 

        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $TermList,

        [String]
        $LastAccessTime,

        [String]
        $LastWriteTime,

        [String]
        $CreationTime,

        [Switch]
        $IncludeC,

        [Switch]
        $IncludeAdmin,

        [Switch]
        $ExcludeFolders,

        [Switch]
        $ExcludeHidden,

        [Switch]
        $CheckWriteAccess,

        [String]
        $OutFile,

        [Switch]
        $NoClobber,

        [Switch]
        $NoPing,

        [UInt32]
        $Delay = 0,

        [Double]
        $Jitter = .3,

        [String]
        $Domain,

        [String]
        $DomainController,
        
        [Switch]
        $SearchForest,

        [Switch]
        $SearchSYSVOL,

        [ValidateRange(1,100)] 
        [Int]
        $Threads,

        [Switch]
        $UsePSDrive
    )

    begin {
        if ($PSBoundParameters['Debug']) {
            $DebugPreference = 'Continue'
        }

        # random object for delay
        $RandNo = New-Object System.Random

        Write-Verbose "[*] Running Invoke-FileFinder with delay of $Delay"

        $Shares = @()

        # figure out the shares we want to ignore
        [String[]] $ExcludedShares = @("C$", "ADMIN$")

        # see if we're specifically including any of the normally excluded sets
        if ($IncludeC) {
            if ($IncludeAdmin) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @("ADMIN$")
            }
        }

        if ($IncludeAdmin) {
            if ($IncludeC) {
                $ExcludedShares = @()
            }
            else {
                $ExcludedShares = @("C$")
            }
        }

        # delete any existing output file if it already exists
        if(!$NoClobber) {
            if ($OutFile -and (Test-Path -Path $OutFile)) { Remove-Item -Path $OutFile }
        }

        # if there's a set of terms specified to search for
        if ($TermList) {
            ForEach ($Term in Get-Content -Path $TermList) {
                if (($Term -ne $Null) -and ($Term.trim() -ne '')) {
                    $SearchTerms += $Term
                }
            }
        }

        # if we're hard-passed a set of shares
        if($ShareList) {
            ForEach ($Item in Get-Content -Path $ShareList) {
                if (($Item -ne $Null) -and ($Item.trim() -ne '')) {
                    # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                    $Share = $Item.Split("`t")[0]
                    $Shares += $Share
                }
            }
        }
        else {
            # if we're using a host file list, read the targets in and add them to the target list
            if($ComputerFile) {
                $ComputerName = Get-Content -Path $ComputerFile
            }

            if(!$ComputerName) {

                if($Domain) {
                    $TargetDomains = @($Domain)
                }
                elseif($SearchForest) {
                    # get ALL the domains in the forest to search
                    $TargetDomains = Get-ThisThingForestDomain | ForEach-Object { $_.Name }
                }
                else {
                    # use the local domain
                    $TargetDomains = @( (Get-ThisThingDomain).name )
                }

                if($SearchSYSVOL) {
                    ForEach ($Domain in $TargetDomains) {
                        $DCSearchPath = "\\$Domain\SYSVOL\"
                        Write-Verbose "[*] Adding share search path $DCSearchPath"
                        $Shares += $DCSearchPath
                    }
                    if(!$SearchTerms) {
                        # search for interesting scripts on SYSVOL
                        $SearchTerms = @('.vbs', '.bat', '.ps1')
                    }
                }
                else {
                    [array]$ComputerName = @()

                    ForEach ($Domain in $TargetDomains) {
                        Write-Verbose "[*] Querying domain $Domain for hosts"
                        $ComputerName += Get-ThisThingComputer -Filter $ComputerFilter -ADSpath $ComputerADSpath -Domain $Domain -DomainController $DomainController
                    }

                    # remove any null target hosts, uniquify the list and shuffle it
                    $ComputerName = $ComputerName | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { Get-Random }
                    if($($ComputerName.Count) -eq 0) {
                        throw "No hosts found!"
                    }
                }
            }
        }

        # script block that enumerates shares and files on a server
        $HostEnumBlock = {
            param($ComputerName, $Ping, $ExcludedShares, $SearchTerms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive)

            Write-Verbose "ComputerName: $ComputerName"
            Write-Verbose "ExcludedShares: $ExcludedShares"
            $SearchShares = @()

            if($ComputerName.StartsWith("\\")) {
                # if a share is passed as the server
                $SearchShares += $ComputerName
            }
            else {
                # if we're enumerating the shares on the target server first
                $Up = $True
                if($Ping) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $ComputerName
                }
                if($Up) {
                    # get the shares for this host and display what we find
                    $Shares = Get-MySMBShare -ComputerName $ComputerName
                    ForEach ($Share in $Shares) {

                        $NetName = $Share.shi1_netname
                        $Path = '\\'+$ComputerName+'\'+$NetName

                        # make sure we get a real share name back
                        if (($NetName) -and ($NetName.trim() -ne '')) {

                            # skip this share if it's in the exclude list
                            if ($ExcludedShares -NotContains $NetName.ToUpper()) {
                                # check if the user has access to this path
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $SearchShares += $Path
                                }
                                catch {
                                    Write-Verbose "[!] No access to $Path"
                                }
                            }
                        }
                    }
                }
            }

            ForEach($Share in $SearchShares) {
                $SearchArgs =  @{
                    'Path' = $Share
                    'SearchTerms' = $SearchTerms
                    'OfficeDocs' = $OfficeDocs
                    'FreshEXEs' = $FreshEXEs
                    'LastAccessTime' = $LastAccessTime
                    'LastWriteTime' = $LastWriteTime
                    'CreationTime' = $CreationTime
                    'ExcludeFolders' = $ExcludeFolders
                    'ExcludeHidden' = $ExcludeHidden
                    'CheckWriteAccess' = $CheckWriteAccess
                    'OutFile' = $OutFile
                    'UsePSDrive' = $UsePSDrive
                }

                Find-InterestingFile @SearchArgs
            }
        }
    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            # if we're using threading, kick off the script block with Invoke-ThreadedFunction
            $ScriptParams = @{
                'Ping' = $(-not $NoPing)
                'ExcludedShares' = $ExcludedShares
                'SearchTerms' = $SearchTerms
                'ExcludeFolders' = $ExcludeFolders
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'OutFile' = $OutFile
                'UsePSDrive' = $UsePSDrive
            }

            # kick off the threaded script block + arguments 
            if($Shares) {
                # pass the shares as the hosts so the threaded function code doesn't have to be hacked up
                Invoke-ThreadedFunction -ComputerName $Shares -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
            }
            else {
                Invoke-ThreadedFunction -ComputerName $ComputerName -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
            }
        }

        else {
            if($Shares){
                $ComputerName = $Shares
            }
            elseif(-not $NoPing -and ($ComputerName.count -gt 1)) {
                # ping all hosts in parallel
                $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
                $ComputerName = Invoke-ThreadedFunction -NoImports -ComputerName $ComputerName -ScriptBlock $Ping -Threads 100
            }

            Write-Verbose "[*] Total number of active hosts: $($ComputerName.count)"
            $Counter = 0

            $ComputerName | Where-Object {$_} | ForEach-Object {
                Write-Verbose "Computer: $_"
                $Counter = $Counter + 1

                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                Write-Verbose "[*] Enumerating server $_ ($Counter of $($ComputerName.count))"

                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $_, $False, $ExcludedShares, $SearchTerms, $ExcludeFolders, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $OutFile, $UsePSDrive                
            }
        }
    }
}


function Get-ThisThingDomainTrust {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $API,

        [Switch]
        $LDAP,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        $TrustAttributes = @{
            [uint32]'0x00000001' = 'non_transitive'
            [uint32]'0x00000002' = 'uplevel_only'
            [uint32]'0x00000004' = 'quarantined_domain'
            [uint32]'0x00000008' = 'forest_transitive'
            [uint32]'0x00000010' = 'cross_organization'
            [uint32]'0x00000020' = 'within_forest'
            [uint32]'0x00000040' = 'treat_as_external'
            [uint32]'0x00000080' = 'trust_uses_rc4_encryption'
            [uint32]'0x00000100' = 'trust_uses_aes_keys'
            [uint32]'0x00000200' = 'cross_organization_no_tgt_delegation'
            [uint32]'0x00000400' = 'pim_trust'
        }
    }

    process {

        if(-not $Domain) {
            # if not domain is specified grab the current domain
            $SourceDomain = (Get-ThisThingDomain -Credential $Credential).Name
        }
        else {
            $SourceDomain = $Domain
        }

        if($LDAP -or $ADSPath) {

            $TrustSearcher = Get-DomainSearcher -Domain $SourceDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -ADSpath $ADSpath

            $SourceSID = Get-DomainSID -Domain $SourceDomain -DomainController $DomainController

            if($TrustSearcher) {

                $TrustSearcher.Filter = '(objectClass=trustedDomain)'

                $Results = $TrustSearcher.FindAll()
                $Results | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject
                    
                    $TrustAttrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }

                    $Direction = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }
                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $TargetSID = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value
                    $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
                    $DomainTrust | Add-Member Noteproperty 'SourceSID' $SourceSID
                    $DomainTrust | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    $DomainTrust | Add-Member Noteproperty 'TargetSID' $TargetSID
                    $DomainTrust | Add-Member Noteproperty 'ObjectGuid' "{$ObjectGuid}"
                    $DomainTrust | Add-Member Noteproperty 'TrustType' $($TrustAttrib -join ',')
                    $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$Direction"
                    $DomainTrust.PSObject.TypeNames.Add('PowerView.DomainTrustLDAP')
                    $DomainTrust
                }
                $Results.dispose()
                $TrustSearcher.dispose()
            }
        }
        elseif($API) {
            if(-not $DomainController) {
                $DomainController = Get-ThisThingDomainController -Credential $Credential -Domain $SourceDomain | Select-Object -First 1 | Select-Object -ExpandProperty Name
            }

            if($DomainController) {
                # arguments for DsEnumerateDomainTrusts
                $PtrInfo = [IntPtr]::Zero

                # 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
                $Flags = 63
                $DomainCount = 0

                # get the trust information from the target server
                $Result = $Netapi32::DsEnumerateDomainTrusts($DomainController, $Flags, [ref]$PtrInfo, [ref]$DomainCount)

                # Locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    $Increment = $DS_DOMAIN_TRUSTS::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $DomainCount); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $DS_DOMAIN_TRUSTS

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ""
                        $Result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $DomainTrust = New-Object PSObject
                            $DomainTrust | Add-Member Noteproperty 'SourceDomain' $SourceDomain
                            $DomainTrust | Add-Member Noteproperty 'SourceDomainController' $DomainController
                            $DomainTrust | Add-Member Noteproperty 'NetbiosDomainName' $Info.NetbiosDomainName
                            $DomainTrust | Add-Member Noteproperty 'DnsDomainName' $Info.DnsDomainName
                            $DomainTrust | Add-Member Noteproperty 'Flags' $Info.Flags
                            $DomainTrust | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                            $DomainTrust | Add-Member Noteproperty 'TrustType' $Info.TrustType
                            $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                            $DomainTrust | Add-Member Noteproperty 'DomainSid' $SidString
                            $DomainTrust | Add-Member Noteproperty 'DomainGuid' $Info.DomainGuid
                            $DomainTrust.PSObject.TypeNames.Add('PowerView.APIDomainTrust')
                            $DomainTrust
                        }
                    }
                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                }
                else {
                    Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                Write-Verbose "Could not retrieve domain controller for $Domain"
            }
        }
        else {
            # if we're using direct domain connections through .NET
            $FoundDomain = Get-ThisThingDomain -Domain $Domain -Credential $Credential
            if($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Add('PowerView.DomainTrust')
                    $_
                }
            }
        }
    }
}


function Get-ThisThingForestTrust {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $Forest,

        [Management.Automation.PSCredential]
        $Credential
    )

    process {
        $FoundForest = Get-ThisThingForest -Forest $Forest -Credential $Credential

        if($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Add('PowerView.ForestTrust')
                $_
            }
        }
    }
}


function Find-ForeignUser {
    [CmdletBinding()]
    param(
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function Get-ForeignUser {
        # helper used to enumerate users who are in groups outside of their principal domain
        param(
            [String]
            $UserName,

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if ($Domain) {
            # get the domain name into distinguished form
            $DistinguishedDomainName = "DC=" + $Domain -replace '\.',',DC='
        }
        else {
            $DistinguishedDomainName = [String] ([adsi]'').distinguishedname
            $Domain = $DistinguishedDomainName -replace 'DC=','' -replace ',','.'
        }

        Get-ThisThingUser -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize -Filter '(memberof=*)' | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf("DC=")
                if($Index) {
                    
                    $GroupDomain = $($Membership.substring($Index)) -replace 'DC=','' -replace ',','.'
                    
                    if ($GroupDomain.CompareTo($Domain)) {
                        # if the group domain doesn't match the user domain, output
                        $GroupName = $Membership.split(",")[0].split("=")[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty 'UserDomain' $Domain
                        $ForeignUser | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty 'GroupDomain' $GroupDomain
                        $ForeignUser | Add-Member Noteproperty 'GroupName' $GroupName
                        $ForeignUser | Add-Member Noteproperty 'GroupDN' $Membership
                        $ForeignUser
                    }
                }
            }
        }
    }

    if ($Recurse) {
        # get all rechable domains in the trust mesh and uniquify them
        if($LDAP -or $DomainController) {
            $DomainTrusts = Invoke-MapDomainTrust -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = Invoke-MapDomainTrust -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {
            # get the trust groups for each domain in the trust mesh
            Write-Verbose "Enumerating trust groups in domain $DomainTrust"
            Get-ForeignUser -Domain $DomainTrust -UserName $UserName -PageSize $PageSize
        }
    }
    else {
        Get-ForeignUser -Domain $Domain -DomainController $DomainController -UserName $UserName -PageSize $PageSize
    }
}


function Find-ForeignGroup {

    [CmdletBinding()]
    param(
        [String]
        $GroupName = '*',

        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP,

        [Switch]
        $Recurse,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    function Get-ForeignGroup {
        param(
            [String]
            $GroupName = '*',

            [String]
            $Domain,

            [String]
            $DomainController,

            [ValidateRange(1,10000)] 
            [Int]
            $PageSize = 200
        )

        if(-not $Domain) {
            $Domain = (Get-ThisThingDomain).Name
        }

        $DomainDN = "DC=$($Domain.Replace('.', ',DC='))"
        Write-Verbose "DomainDN: $DomainDN"

        # standard group names to ignore
        $ExcludeGroups = @("Users", "Domain Users", "Guests")

        # get all the groupnames for the given domain
        Get-ThisThingGroup -GroupName $GroupName -Filter '(member=*)' -Domain $Domain -DomainController $DomainController -FullData -PageSize $PageSize | Where-Object {
            # exclude common large groups
            -not ($ExcludeGroups -contains $_.samaccountname) } | ForEach-Object {
                
                $GroupName = $_.samAccountName

                $_.member | ForEach-Object {
                    # filter for foreign SIDs in the cn field for users in another domain,
                    #   or if the DN doesn't end with the proper DN for the queried domain  
                    if (($_ -match 'CN=S-1-5-21.*-.*') -or ($DomainDN -ne ($_.substring($_.IndexOf("DC="))))) {

                        $UserDomain = $_.subString($_.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        $UserName = $_.split(",")[0].split("=")[1]

                        $ForeignGroupUser = New-Object PSObject
                        $ForeignGroupUser | Add-Member Noteproperty 'GroupDomain' $Domain
                        $ForeignGroupUser | Add-Member Noteproperty 'GroupName' $GroupName
                        $ForeignGroupUser | Add-Member Noteproperty 'UserDomain' $UserDomain
                        $ForeignGroupUser | Add-Member Noteproperty 'UserName' $UserName
                        $ForeignGroupUser | Add-Member Noteproperty 'UserDN' $_
                        $ForeignGroupUser
                    }
                }
        }
    }

    if ($Recurse) {
        # get all rechable domains in the trust mesh and uniquify them
        if($LDAP -or $DomainController) {
            $DomainTrusts = Invoke-MapDomainTrust -LDAP -DomainController $DomainController -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }
        else {
            $DomainTrusts = Invoke-MapDomainTrust -PageSize $PageSize | ForEach-Object { $_.SourceDomain } | Sort-Object -Unique
        }

        ForEach($DomainTrust in $DomainTrusts) {
            # get the trust groups for each domain in the trust mesh
            Write-Verbose "Enumerating trust groups in domain $DomainTrust"
            Get-ForeignGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
        }
    }
    else {
        Get-ForeignGroup -GroupName $GroupName -Domain $Domain -DomainController $DomainController -PageSize $PageSize
    }
}


function Find-ManagedSecurityGroups {

    # Go through the list of security groups on the domain and identify those who have a manager
    Get-ThisThingGroup -FullData -Filter '(managedBy=*)' | Select-Object -Unique distinguishedName,managedBy,cn | ForEach-Object {

        # Retrieve the object that the managedBy DN refers to
        $group_manager = Get-ADObject -ADSPath $_.managedBy | Select-Object cn,distinguishedname,name,samaccounttype,samaccountname

        # Create a results object to store our findings
        $results_object = New-Object -TypeName PSObject -Property @{
            'GroupCN' = $_.cn
            'GroupDN' = $_.distinguishedname
            'ManagerCN' = $group_manager.cn
            'ManagerDN' = $group_manager.distinguishedName
            'ManagerSAN' = $group_manager.samaccountname
            'ManagerType' = ''
            'CanManagerWrite' = $FALSE
        }

        # Determine whether the manager is a user or a group
        if ($group_manager.samaccounttype -eq 0x10000000) {
            $results_object.ManagerType = 'Group'
        } elseif ($group_manager.samaccounttype -eq 0x30000000) {
            $results_object.ManagerType = 'User'
        }

        # Find the ACLs that relate to the ability to write to the group
        $xacl = Get-ObjectAcl -ADSPath $_.distinguishedname -Rights WriteMembers

        # Double-check that the manager
        if ($xacl.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2' -and $xacl.AccessControlType -eq 'Allow' -and $xacl.IdentityReference.Value.Contains($group_manager.samaccountname)) {
            $results_object.CanManagerWrite = $TRUE
        }
        $results_object
    }
}


function Invoke-MapDomainTrust {
    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,

        [String]
        $DomainController,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    # keep track of domains seen so we don't hit infinite recursion
    $SeenDomains = @{}

    # our domain status tracker
    $Domains = New-Object System.Collections.Stack

    # get the current domain and push it onto the stack
    $CurrentDomain = (Get-ThisThingDomain -Credential $Credential).Name
    $Domains.push($CurrentDomain)

    while($Domains.Count -ne 0) {

        $Domain = $Domains.Pop()

        # if we haven't seen this domain before
        if ($Domain -and ($Domain.Trim() -ne "") -and (-not $SeenDomains.ContainsKey($Domain))) {
            
            Write-Verbose "Enumerating trusts for domain '$Domain'"

            # mark it as seen in our list
            $Null = $SeenDomains.add($Domain, "")

            try {
                # get all the trusts for this domain
                if($LDAP -or $DomainController) {
                    $Trusts = Get-ThisThingDomainTrust -Domain $Domain -LDAP -DomainController $DomainController -PageSize $PageSize -Credential $Credential
                }
                else {
                    $Trusts = Get-ThisThingDomainTrust -Domain $Domain -PageSize $PageSize -Credential $Credential
                }

                if($Trusts -isnot [System.Array]) {
                    $Trusts = @($Trusts)
                }

                # get any forest trusts, if they exist
                if(-not ($LDAP -or $DomainController) ) {
                    $Trusts += Get-ThisThingForestTrust -Forest $Domain -Credential $Credential
                }

                if ($Trusts) {
                    if($Trusts -isnot [System.Array]) {
                        $Trusts = @($Trusts)
                    }

                    # enumerate each trust found
                    ForEach ($Trust in $Trusts) {
                        if($Trust.SourceName -and $Trust.TargetName) {
                            $SourceDomain = $Trust.SourceName
                            $TargetDomain = $Trust.TargetName
                            $TrustType = $Trust.TrustType
                            $TrustDirection = $Trust.TrustDirection
                            $ObjectType = $Trust.PSObject.TypeNames | Where-Object {$_ -match 'PowerView'} | Select-Object -First 1

                            # make sure we process the target
                            $Null = $Domains.Push($TargetDomain)

                            # build the nicely-parsable custom output object
                            $DomainTrust = New-Object PSObject
                            $DomainTrust | Add-Member Noteproperty 'SourceDomain' "$SourceDomain"
                            $DomainTrust | Add-Member Noteproperty 'SourceSID' $Trust.SourceSID
                            $DomainTrust | Add-Member Noteproperty 'TargetDomain' "$TargetDomain"
                            $DomainTrust | Add-Member Noteproperty 'TargetSID' $Trust.TargetSID
                            $DomainTrust | Add-Member Noteproperty 'TrustType' "$TrustType"
                            $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$TrustDirection"
                            $DomainTrust.PSObject.TypeNames.Add($ObjectType)
                            $DomainTrust
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[!] Error: $_"
            }
        }
    }
}

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr]))
)

# enum used by $WTS_SESSION_INFO_1 below
$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
$WTS_SESSION_INFO_1 = struct $Mod WTS_SESSION_INFO_1 @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
$WKSTA_USER_INFO_1 = struct $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupGetMembers result structure
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}

# enums used in DS_DOMAIN_TRUSTS
$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Wtsapi32 = $Types['wtsapi32']

function Invoke-Parallel
{
    [cmdletbinding(DefaultParameterSetName = 'ScriptBlock')]
    Param (
        [Parameter(Mandatory = $false,position = 0,ParameterSetName = 'ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false,ParameterSetName = 'ScriptFile')]
        [ValidateScript({
                    Test-Path $_ -PathType leaf
        })]
        $ScriptFile,

        [Parameter(Mandatory = $true,ValueFromPipeline = $true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportSessionFunctions,

        [switch]$ImportVariables,

        [switch]$ImportModules,

        [int]$Throttle = 20,

        [int]$SleepTimer = 200,

        [int]$RunspaceTimeout = 0,

        [switch]$NoCloseOnTimeout = $false,

        [int]$MaxQueue,

        [validatescript({
                    Test-Path (Split-Path -Path $_ -Parent)
        })]
        [string]$LogFile = 'C:\temp\log.log',

        [switch] $Quiet = $false
    )

    Begin {

        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
        {
            if($RunspaceTimeout -ne 0)
            {
                $script:MaxQueue = $Throttle
            }
            else
            {
                $script:MaxQueue = $Throttle * 3
            }
        }
        else
        {
            $script:MaxQueue = $MaxQueue
        }

        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules)
        {
            $StandardUserEnv = [powershell]::Create().addscript({
                    #Get modules and snapins in this clean runspace
                    $Modules = Get-Module | Select-Object -ExpandProperty Name
                    $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name

                    #Get variables in this clean runspace
                    #Called last to get vars like $? into session
                    $Variables = Get-Variable | Select-Object -ExpandProperty Name

                    #Return a hashtable where we can access each.
                    @{
                        Variables = $Variables
                        Modules   = $Modules
                        Snapins   = $Snapins
                    }
            }).invoke()[0]

            if ($ImportVariables)
            {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp
                {
                    [cmdletbinding()] param()
                }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object -FilterScript {
                        -not ($VariablesToExclude -contains $_.Name)
                } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"
            }

            if ($ImportModules)
            {
                $UserModules = @( Get-Module |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path -Path $_.Path -ErrorAction SilentlyContinue)
                    } |
                Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin |
                    Select-Object -ExpandProperty Name |
                    Where-Object -FilterScript {
                        $StandardUserEnv.Snapins -notcontains $_
                } )
            }
        }

        #region functions

        Function Get-RunspaceData
        {
            [cmdletbinding()]
            param( [switch]$Wait )

            #loop through runspaces
            #if $wait is specified, keep looping until all complete
            Do
            {
                #set more to false for tracking completion
                $more = $false

                #Progress bar if we have inputobject count (bound parameter)
                if (-not $Quiet)
                {
                    Write-Progress  -Activity 'Running Query' -Status 'Starting threads'`
                    -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                    -PercentComplete $( Try
                        {
                            $script:completedCount / $totalCount * 100
                        }
                        Catch
                        {
                            0
                        }
                    )
                }

                #run through each runspace.
                Foreach($runspace in $runspaces)
                {
                    #get the duration - inaccurate
                    $currentdate = Get-Date
                    $runtime = $currentdate - $runspace.startTime
                    $runMin = [math]::Round( $runtime.totalminutes ,2 )

                    #set up log object
                    $log = '' | Select-Object -Property Date, Action, Runtime, Status, Details
                    $log.Action = "Removing:'$($runspace.object)'"
                    $log.Date = $currentdate
                    $log.Runtime = "$runMin minutes"

                    #If runspace completed, end invoke, dispose, recycle, counter++
                    If ($runspace.Runspace.isCompleted)
                    {
                        $script:completedCount++

                        #check if there were errors
                        if($runspace.powershell.Streams.Error.Count -gt 0)
                        {
                            #set the logging info and move the file to completed
                            $log.status = 'CompletedWithErrors'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            foreach($ErrorRecord in $runspace.powershell.Streams.Error)
                            {
                                Write-Error -ErrorRecord $ErrorRecord
                            }
                        }
                        else
                        {
                            #add logging details and cleanup
                            $log.status = 'Completed'
                            #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        }

                        #everything is logged, clean up the runspace
                        $runspace.powershell.EndInvoke($runspace.Runspace)
                        $runspace.powershell.dispose()
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                    }

                    #If runtime exceeds max, dispose the runspace
                    ElseIf ( $RunspaceTimeout -ne 0 -and $runtime.totalseconds -gt $RunspaceTimeout)
                    {
                        $script:completedCount++
                        $timedOutTasks = $true

                        #add logging details and cleanup
                        $log.status = 'TimedOut'
                        #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                        Write-Error -Message "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | Out-String)"

                        #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                        if (!$NoCloseOnTimeout)
                        {
                            $runspace.powershell.dispose()
                        }
                        $runspace.Runspace = $null
                        $runspace.powershell = $null
                        $completedCount++
                    }

                    #If runspace isn't null set more to true
                    ElseIf ($runspace.Runspace -ne $null )
                    {
                        $log = $null
                        $more = $true
                    }

                    #log the results if a log file was indicated
                    <#
                            if($logFile -and $log){
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                            }
                    #>
                }

                #Clean out unused runspace jobs
                $temphash = $runspaces.clone()
                $temphash |
                Where-Object -FilterScript {
                    $_.runspace -eq $null
                } |
                ForEach-Object -Process {
                    $runspaces.remove($_)
                }

                #sleep for a bit if we will loop again
                if($PSBoundParameters['Wait'])
                {
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #Loop again only if -wait parameter and there are more runspaces to process
            }
            while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
        }

        #endregion functions

        #region Init

        if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
        {
            $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | Out-String) )
        }
        elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
        {
            #Start building parameter names for the param block
            [string[]]$ParamsToAdd = '$_'
            if( $PSBoundParameters.ContainsKey('Parameter') )
            {
                $ParamsToAdd += '$Parameter'
            }

            $UsingVariableData = $null


            # This code enables $Using support through the AST.
            # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

            if($PSVersionTable.PSVersion.Major -gt 2)
            {
                #Extract using references
                $UsingVariables = $ScriptBlock.ast.FindAll({
                        $args[0] -is [System.Management.Automation.Language.UsingExpressionAst]
                },$true)

                If ($UsingVariables)
                {
                    $List = New-Object -TypeName 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                    ForEach ($Ast in $UsingVariables)
                    {
                        [void]$List.Add($Ast.SubExpression)
                    }

                    $UsingVar = $UsingVariables |
                    Group-Object -Property SubExpression |
                    ForEach-Object -Process {
                        $_.Group |
                        Select-Object -First 1
                    }

                    #Extract the name, value, and create replacements for each
                    $UsingVariableData = ForEach ($Var in $UsingVar)
                    {
                        Try
                        {
                            $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                            [pscustomobject]@{
                                Name       = $Var.SubExpression.Extent.Text
                                Value      = $Value.Value
                                NewName    = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                            }
                        }
                        Catch
                        {
                            Write-Error -Message "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                        }
                    }
                    $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                    $NewParams = $UsingVariableData.NewName -join ', '
                    $Tuple = [Tuple]::Create($List, $NewParams)
                    $bindingFlags = [Reflection.BindingFlags]'Default,NonPublic,Instance'
                    $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                    $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                    $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                    #Write-Verbose $StringScriptBlock
                }
            }

            $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ', '))`r`n" + $ScriptBlock.ToString())
        }
        else
        {
            Throw 'Must provide ScriptBlock or ScriptFile'
            Break
        }

        Write-Debug -Message "`$ScriptBlock: $($ScriptBlock | Out-String)"
        If (-not($SuppressVerbose)){
            Write-Verbose -Message 'Creating runspace pool and session states'
        }


        #If specified, add variables and modules/snapins to session state
        $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        if ($ImportVariables)
        {
            if($UserVariables.count -gt 0)
            {
                foreach($Variable in $UserVariables)
                {
                    $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
        }
        if ($ImportModules)
        {
            if($UserModules.count -gt 0)
            {
                foreach($ModulePath in $UserModules)
                {
                    $sessionstate.ImportPSModule($ModulePath)
                }
            }
            if($UserSnapins.count -gt 0)
            {
                foreach($PSSnapin in $UserSnapins)
                {
                    [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                }
            }
        }

        # --------------------------------------------------
        #region - Import Session Functions
        # --------------------------------------------------
        # Import functions from the current session into the RunspacePool sessionstate

        if($ImportSessionFunctions)
        {
            # Import all session functions into the runspace session state from the current one
            Get-ChildItem -Path Function:\ |
            Where-Object -FilterScript {
                $_.name -notlike '*:*'
            } |
            Select-Object -Property name -ExpandProperty name |
            ForEach-Object -Process {
                # Get the function code
                $Definition = Get-Content -Path "function:\$_" -ErrorAction Stop

                # Create a sessionstate function with the same name and code
                $SessionStateFunction = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "$_", $Definition

                # Add the function to the session state
                $sessionstate.Commands.Add($SessionStateFunction)
            }
        }
        #endregion

        #Create runspace pool
        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
        $runspacepool.Open()

        #Write-Verbose "Creating empty collection to hold runspace jobs"
        $Script:runspaces = New-Object -TypeName System.Collections.ArrayList

        #If inputObject is bound get a total count and set bound to true
        $bound = $PSBoundParameters.keys -contains 'InputObject'
        if(-not $bound)
        {
            [System.Collections.ArrayList]$allObjects = @()
        }

        <#
                #Set up log file if specified
                if( $LogFile ){
                New-Item -ItemType file -path $logFile -force | Out-Null
                ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                }

                #write initial log entry
                $log = "" | Select Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
        #>
        $timedOutTasks = $false

        #endregion INIT
    }

    Process {

        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound)
        {
            $allObjects = $InputObject
        }
        Else
        {
            [void]$allObjects.add( $InputObject )
        }
    }

    End {

        #Use Try/Finally to catch Ctrl+C and clean up.
        Try
        {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0

            foreach($object in $allObjects)
            {
                #region add scripts to runspace pool

                #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                $powershell = [powershell]::Create()

                if ($VerbosePreference -eq 'Continue')
                {
                    [void]$powershell.AddScript({
                            $VerbosePreference = 'Continue'
                    })
                }

                [void]$powershell.AddScript($ScriptBlock).AddArgument($object)

                if ($Parameter)
                {
                    [void]$powershell.AddArgument($Parameter)
                }

                # $Using support from Boe Prox
                if ($UsingVariableData)
                {
                    Foreach($UsingVariable in $UsingVariableData)
                    {
                        #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                        [void]$powershell.AddArgument($UsingVariable.Value)
                    }
                }

                #Add the runspace into the powershell instance
                $powershell.RunspacePool = $runspacepool

                #Create a temporary collection for each runspace
                $temp = '' | Select-Object -Property PowerShell, StartTime, object, Runspace
                $temp.PowerShell = $powershell
                $temp.StartTime = Get-Date
                $temp.object = $object

                #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                $temp.Runspace = $powershell.BeginInvoke()
                $startedCount++

                #Add the temp tracking info to $runspaces collection
                #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                $null = $runspaces.Add($temp)

                #loop through existing runspaces one time
                Get-RunspaceData

                #If we have more running than max queue (used to control timeout accuracy)
                #Script scope resolves odd PowerShell 2 issue
                $firstRun = $true
                while ($runspaces.count -ge $script:MaxQueue)
                {
                    #give verbose output
                    if($firstRun)
                    {
                        #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                    }
                    $firstRun = $false

                    #run get-runspace data and sleep for a short while
                    Get-RunspaceData
                    Start-Sleep -Milliseconds $SleepTimer
                }

                #endregion add scripts to runspace pool
            }

            #Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
            Get-RunspaceData -wait

            if (-not $Quiet)
            {
                Write-Progress -Activity 'Running Query' -Status 'Starting threads' -Completed
            }
        }
        Finally
        {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($NoCloseOnTimeout -eq $false) ) )
            {
                If (-not($SuppressVerbose)){
                    Write-Verbose -Message 'Closing the runspace pool'
                }
                $runspacepool.close()
            }

            #collect garbage
            [gc]::Collect()
        }
    }
}

Function Invoke-Ping 
{
<#
.SYNOPSIS
    Ping or test connectivity to systems in parallel
    
.DESCRIPTION
    Ping or test connectivity to systems in parallel

    Default action will run a ping against systems
        If Quiet parameter is specified, we return an array of systems that responded
        If Detail parameter is specified, we test WSMan, RemoteReg, RPC, RDP and/or SMB

.PARAMETER ComputerName
    One or more computers to test

.PARAMETER Quiet
    If specified, only return addresses that responded to Test-Connection

.PARAMETER Detail
    Include one or more additional tests as specified:
        WSMan      via Test-WSMan
        RemoteReg  via Microsoft.Win32.RegistryKey
        RPC        via WMI
        RDP        via port 3389
        SMB        via \\ComputerName\C$
        *          All tests

.PARAMETER Timeout
    Time in seconds before we attempt to dispose an individual query.  Default is 20

.PARAMETER Throttle
    Throttle query to this many parallel runspaces.  Default is 100.

.PARAMETER NoCloseOnTimeout
    Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out

    This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

.EXAMPLE
    Invoke-Ping Server1, Server2, Server3 -Detail *

    # Check for WSMan, Remote Registry, Remote RPC, RDP, and SMB (via C$) connectivity against 3 machines

.EXAMPLE
    $Computers | Invoke-Ping

    # Ping computers in $Computers in parallel

.EXAMPLE
    $Responding = $Computers | Invoke-Ping -Quiet
    
    # Create a list of computers that successfully responded to Test-Connection

.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Invoke-Ping-Test-in-b553242a

.FUNCTIONALITY
    Computers

#>
    [cmdletbinding(DefaultParameterSetName='Ping')]
    param(
        [Parameter( ValueFromPipeline=$true,
                    ValueFromPipelineByPropertyName=$true, 
                    Position=0)]
        [string[]]$ComputerName,
        
        [Parameter( ParameterSetName='Detail')]
        [validateset("*","WSMan","RemoteReg","RPC","RDP","SMB")]
        [string[]]$Detail,
        
        [Parameter(ParameterSetName='Ping')]
        [switch]$Quiet,
        
        [int]$Timeout = 20,
        
        [int]$Throttle = 100,

        [switch]$NoCloseOnTimeout
    )
    Begin
    {

        #http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
        function Invoke-Parallel {
            [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
            Param (   
                [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
                    [System.Management.Automation.ScriptBlock]$ScriptBlock,

                [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
                [ValidateScript({test-path $_ -pathtype leaf})]
                    $ScriptFile,

                [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Alias('CN','__Server','IPAddress','Server','ComputerName')]    
                    [PSObject]$InputObject,

                    [PSObject]$Parameter,

                    [switch]$ImportVariables,

                    [switch]$ImportModules,

                    [int]$Throttle = 20,

                    [int]$SleepTimer = 200,

                    [int]$RunspaceTimeout = 0,

			        [switch]$NoCloseOnTimeout = $false,

                    [int]$MaxQueue,

                [validatescript({Test-Path (Split-Path $_ -parent)})]
                    [string]$LogFile = "C:\temp\log.log",

			        [switch] $Quiet = $false
            )
    
            Begin {
                
                #No max queue specified?  Estimate one.
                #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
                if( -not $PSBoundParameters.ContainsKey('MaxQueue') )
                {
                    if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
                    else{ $script:MaxQueue = $Throttle * 3 }
                }
                else
                {
                    $script:MaxQueue = $MaxQueue
                }

                Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

                #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
                if ($ImportVariables -or $ImportModules)
                {
                    $StandardUserEnv = [powershell]::Create().addscript({

                        #Get modules and snapins in this clean runspace
                        $Modules = Get-Module | Select -ExpandProperty Name
                        $Snapins = Get-PSSnapin | Select -ExpandProperty Name

                        #Get variables in this clean runspace
                        #Called last to get vars like $? into session
                        $Variables = Get-Variable | Select -ExpandProperty Name
                
                        #Return a hashtable where we can access each.
                        @{
                            Variables = $Variables
                            Modules = $Modules
                            Snapins = $Snapins
                        }
                    }).invoke()[0]
            
                    if ($ImportVariables) {
                        #Exclude common parameters, bound parameters, and automatic variables
                        Function _temp {[cmdletbinding()] param() }
                        $VariablesToExclude = @( (Get-Command _temp | Select -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                        Write-Verbose "Excluding variables $( ($VariablesToExclude | sort ) -join ", ")"

                        # we don't use 'Get-Variable -Exclude', because it uses regexps. 
                        # One of the veriables that we pass is '$?'. 
                        # There could be other variables with such problems.
                        # Scope 2 required if we move to a real module
                        $UserVariables = @( Get-Variable | Where { -not ($VariablesToExclude -contains $_.Name) } ) 
                        Write-Verbose "Found variables to import: $( ($UserVariables | Select -expandproperty Name | Sort ) -join ", " | Out-String).`n"

                    }

                    if ($ImportModules) 
                    {
                        $UserModules = @( Get-Module | Where {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select -ExpandProperty Path )
                        $UserSnapins = @( Get-PSSnapin | Select -ExpandProperty Name | Where {$StandardUserEnv.Snapins -notcontains $_ } ) 
                    }
                }

                #region functions
            
                    Function Get-RunspaceData {
                        [cmdletbinding()]
                        param( [switch]$Wait )

                        #loop through runspaces
                        #if $wait is specified, keep looping until all complete
                        Do {

                            #set more to false for tracking completion
                            $more = $false

                            #Progress bar if we have inputobject count (bound parameter)
                            if (-not $Quiet) {
						        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
							        -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
							        -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
					        }

                            #run through each runspace.           
                            Foreach($runspace in $runspaces) {
                    
                                #get the duration - inaccurate
                                $currentdate = Get-Date
                                $runtime = $currentdate - $runspace.startTime
                                $runMin = [math]::Round( $runtime.totalminutes ,2 )

                                #set up log object
                                $log = "" | select Date, Action, Runtime, Status, Details
                                $log.Action = "Removing:'$($runspace.object)'"
                                $log.Date = $currentdate
                                $log.Runtime = "$runMin minutes"

                                #If runspace completed, end invoke, dispose, recycle, counter++
                                If ($runspace.Runspace.isCompleted) {
                            
                                    $script:completedCount++
                        
                                    #check if there were errors
                                    if($runspace.powershell.Streams.Error.Count -gt 0) {
                                
                                        #set the logging info and move the file to completed
                                        $log.status = "CompletedWithErrors"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                        foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                            Write-Error -ErrorRecord $ErrorRecord
                                        }
                                    }
                                    else {
                                
                                        #add logging details and cleanup
                                        $log.status = "Completed"
                                        Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    }

                                    #everything is logged, clean up the runspace
                                    $runspace.powershell.EndInvoke($runspace.Runspace)
                                    $runspace.powershell.dispose()
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null

                                }

                                #If runtime exceeds max, dispose the runspace
                                ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            
                                    $script:completedCount++
                                    $timedOutTasks = $true
                            
							        #add logging details and cleanup
                                    $log.status = "TimedOut"
                                    Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                    Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                                    #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                                    if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                                    $runspace.Runspace = $null
                                    $runspace.powershell = $null
                                    $completedCount++

                                }
                   
                                #If runspace isn't null set more to true  
                                ElseIf ($runspace.Runspace -ne $null ) {
                                    $log = $null
                                    $more = $true
                                }

                                #log the results if a log file was indicated
                                if($logFile -and $log){
                                    ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                                }
                            }

                            #Clean out unused runspace jobs
                            $temphash = $runspaces.clone()
                            $temphash | Where { $_.runspace -eq $Null } | ForEach {
                                $Runspaces.remove($_)
                            }

                            #sleep for a bit if we will loop again
                            if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                        #Loop again only if -wait parameter and there are more runspaces to process
                        } while ($more -and $PSBoundParameters['Wait'])
                
                    #End of runspace function
                    }

                #endregion functions
        
                #region Init

                    if($PSCmdlet.ParameterSetName -eq 'ScriptFile')
                    {
                        $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
                    }
                    elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock')
                    {
                        #Start building parameter names for the param block
                        [string[]]$ParamsToAdd = '$_'
                        if( $PSBoundParameters.ContainsKey('Parameter') )
                        {
                            $ParamsToAdd += '$Parameter'
                        }

                        $UsingVariableData = $Null
                

                        # This code enables $Using support through the AST.
                        # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!
                
                        if($PSVersionTable.PSVersion.Major -gt 2)
                        {
                            #Extract using references
                            $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)    

                            If ($UsingVariables)
                            {
                                $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                                ForEach ($Ast in $UsingVariables)
                                {
                                    [void]$list.Add($Ast.SubExpression)
                                }

                                $UsingVar = $UsingVariables | Group Parent | ForEach {$_.Group | Select -First 1}
        
                                #Extract the name, value, and create replacements for each
                                $UsingVariableData = ForEach ($Var in $UsingVar) {
                                    Try
                                    {
                                        $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                        $NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        [pscustomobject]@{
                                            Name = $Var.SubExpression.Extent.Text
                                            Value = $Value.Value
                                            NewName = $NewName
                                            NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        }
                                        $ParamsToAdd += $NewName
                                    }
                                    Catch
                                    {
                                        Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                                    }
                                }
    
                                $NewParams = $UsingVariableData.NewName -join ', '
                                $Tuple = [Tuple]::Create($list, $NewParams)
                                $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                                $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))
        
                                $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                                $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                                Write-Verbose $StringScriptBlock
                            }
                        }
                
                        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
                    }
                    else
                    {
                        Throw "Must provide ScriptBlock or ScriptFile"; Break
                    }

                    Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
                    Write-Verbose "Creating runspace pool and session states"

                    #If specified, add variables and modules/snapins to session state
                    $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
                    if ($ImportVariables)
                    {
                        if($UserVariables.count -gt 0)
                        {
                            foreach($Variable in $UserVariables)
                            {
                                $sessionstate.Variables.Add( (New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                            }
                        }
                    }
                    if ($ImportModules)
                    {
                        if($UserModules.count -gt 0)
                        {
                            foreach($ModulePath in $UserModules)
                            {
                                $sessionstate.ImportPSModule($ModulePath)
                            }
                        }
                        if($UserSnapins.count -gt 0)
                        {
                            foreach($PSSnapin in $UserSnapins)
                            {
                                [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                            }
                        }
                    }

                    #Create runspace pool
                    $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
                    $runspacepool.Open() 

                    Write-Verbose "Creating empty collection to hold runspace jobs"
                    $Script:runspaces = New-Object System.Collections.ArrayList        
        
                    #If inputObject is bound get a total count and set bound to true
                    $global:__bound = $false
                    $allObjects = @()
                    if( $PSBoundParameters.ContainsKey("inputObject") ){
                        $global:__bound = $true
                    }

                    #Set up log file if specified
                    if( $LogFile ){
                        New-Item -ItemType file -path $logFile -force | Out-Null
                        ("" | Select Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
                    }

                    #write initial log entry
                    $log = "" | Select Date, Action, Runtime, Status, Details
                        $log.Date = Get-Date
                        $log.Action = "Batch processing started"
                        $log.Runtime = $null
                        $log.Status = "Started"
                        $log.Details = $null
                        if($logFile) {
                            ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                        }

			        $timedOutTasks = $false

                #endregion INIT
            }

            Process {

                #add piped objects to all objects or set all objects to bound input object parameter
                if( -not $global:__bound ){
                    $allObjects += $inputObject
                }
                else{
                    $allObjects = $InputObject
                }
            }

            End {
        
                #Use Try/Finally to catch Ctrl+C and clean up.
                Try
                {
                    #counts for progress
                    $totalCount = $allObjects.count
                    $script:completedCount = 0
                    $startedCount = 0

                    foreach($object in $allObjects){
        
                        #region add scripts to runspace pool
                    
                            #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                            $powershell = [powershell]::Create()
                    
                            if ($VerbosePreference -eq 'Continue')
                            {
                                [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                            }

                            [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                            if ($parameter)
                            {
                                [void]$PowerShell.AddArgument($parameter)
                            }

                            # $Using support from Boe Prox
                            if ($UsingVariableData)
                            {
                                Foreach($UsingVariable in $UsingVariableData) {
                                    Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                                    [void]$PowerShell.AddArgument($UsingVariable.Value)
                                }
                            }

                            #Add the runspace into the powershell instance
                            $powershell.RunspacePool = $runspacepool
    
                            #Create a temporary collection for each runspace
                            $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                            $temp.PowerShell = $powershell
                            $temp.StartTime = Get-Date
                            $temp.object = $object
    
                            #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                            $temp.Runspace = $powershell.BeginInvoke()
                            $startedCount++

                            #Add the temp tracking info to $runspaces collection
                            Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                            $runspaces.Add($temp) | Out-Null
            
                            #loop through existing runspaces one time
                            Get-RunspaceData

                            #If we have more running than max queue (used to control timeout accuracy)
                            #Script scope resolves odd PowerShell 2 issue
                            $firstRun = $true
                            while ($runspaces.count -ge $Script:MaxQueue) {

                                #give verbose output
                                if($firstRun){
                                    Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                                }
                                $firstRun = $false
                    
                                #run get-runspace data and sleep for a short while
                                Get-RunspaceData
                                Start-Sleep -Milliseconds $sleepTimer
                    
                            }

                        #endregion add scripts to runspace pool
                    }
                     
                    Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where {$_.Runspace -ne $Null}).Count) )
                    Get-RunspaceData -wait

                    if (-not $quiet) {
			            Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
		            }

                }
                Finally
                {
                    #Close the runspace pool, unless we specified no close on timeout and something timed out
                    if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
	                    Write-Verbose "Closing the runspace pool"
			            $runspacepool.close()
                    }

                    #collect garbage
                    [gc]::Collect()
                }       
            }
        }

        Write-Verbose "PSBoundParameters = $($PSBoundParameters | Out-String)"
        
        $bound = $PSBoundParameters.keys -contains "ComputerName"
        if(-not $bound)
        {
            [System.Collections.ArrayList]$AllComputers = @()
        }
    }
    Process
    {

        #Handle both pipeline and bound parameter.  We don't want to stream objects, defeats purpose of parallelizing work
        if($bound)
        {
            $AllComputers = $ComputerName
        }
        Else
        {
            foreach($Computer in $ComputerName)
            {
                $AllComputers.add($Computer) | Out-Null
            }
        }

    }
    End
    {

        #Built up the parameters and run everything in parallel
        $params = @($Detail, $Quiet)
        $splat = @{
            Throttle = $Throttle
            RunspaceTimeout = $Timeout
            InputObject = $AllComputers
            parameter = $params
        }
        if($NoCloseOnTimeout)
        {
            $splat.add('NoCloseOnTimeout',$True)
        }

        Invoke-Parallel @splat -ScriptBlock {
        
            $computer = $_.trim()
            $detail = $parameter[0]
            $quiet = $parameter[1]

            #They want detail, define and run test-server
            if($detail)
            {
                Try
                {
                    #Modification of jrich's Test-Server function: https://gallery.technet.microsoft.com/scriptcenter/Powershell-Test-Server-e0cdea9a
                    Function Test-Server{
                        [cmdletBinding()]
                        param(
	                        [parameter(
                                Mandatory=$true,
                                ValueFromPipeline=$true)]
	                        [string[]]$ComputerName,
                            [switch]$All,
                            [parameter(Mandatory=$false)]
	                        [switch]$CredSSP,
                            [switch]$RemoteReg,
                            [switch]$RDP,
                            [switch]$RPC,
                            [switch]$SMB,
                            [switch]$WSMAN,
                            [switch]$IPV6,
	                        [Management.Automation.PSCredential]$Credential
                        )
                            begin
                            {
	                            $total = Get-Date
	                            $results = @()
	                            if($credssp -and -not $Credential)
                                {
                                    Throw "Must supply Credentials with CredSSP test"
                                }

                                [string[]]$props = write-output Name, IP, Domain, Ping, WSMAN, CredSSP, RemoteReg, RPC, RDP, SMB

                                #Hash table to create PSObjects later, compatible with ps2...
                                $Hash = @{}
                                foreach($prop in $props)
                                {
                                    $Hash.Add($prop,$null)
                                }

                                function Test-Port{
                                    [cmdletbinding()]
                                    Param(
                                        [string]$srv,
                                        $port=135,
                                        $timeout=3000
                                    )
                                    $ErrorActionPreference = "SilentlyContinue"
                                    $tcpclient = new-Object system.Net.Sockets.TcpClient
                                    $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
                                    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
                                    if(-not $wait)
                                    {
                                        $tcpclient.Close()
                                        Write-Verbose "Connection Timeout to $srv`:$port"
                                        $false
                                    }
                                    else
                                    {
                                        Try
                                        {
                                            $tcpclient.EndConnect($iar) | out-Null
                                            $true
                                        }
                                        Catch
                                        {
                                            write-verbose "Error for $srv`:$port`: $_"
                                            $false
                                        }
                                        $tcpclient.Close()
                                    }
                                }
                            }

                            process
                            {
                                foreach($name in $computername)
                                {
	                                $dt = $cdt= Get-Date
	                                Write-verbose "Testing: $Name"
	                                $failed = 0
	                                try{
	                                    $DNSEntity = [Net.Dns]::GetHostEntry($name)
	                                    $domain = ($DNSEntity.hostname).replace("$name.","")
	                                    $ips = $DNSEntity.AddressList | %{
                                            if(-not ( -not $IPV6 -and $_.AddressFamily -like "InterNetworkV6" ))
                                            {
                                                $_.IPAddressToString
                                            }
                                        }
	                                }
	                                catch
	                                {
		                                $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
		                                $rst.name = $name
		                                $results += $rst
		                                $failed = 1
	                                }
	                                Write-verbose "DNS:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
	                                if($failed -eq 0){
	                                    foreach($ip in $ips)
	                                    {
	    
		                                    $rst = New-Object -TypeName PSObject -Property $Hash | Select -Property $props
	                                        $rst.name = $name
		                                    $rst.ip = $ip
		                                    $rst.domain = $domain
		            
                                            if($RDP -or $All)
                                            {
                                                ####RDP Check (firewall may block rest so do before ping
		                                        try{
                                                    $socket = New-Object Net.Sockets.TcpClient($name, 3389) -ErrorAction stop
		                                            if($socket -eq $null)
		                                            {
			                                            $rst.RDP = $false
		                                            }
		                                            else
		                                            {
			                                            $rst.RDP = $true
			                                            $socket.close()
		                                            }
                                                }
                                                catch
                                                {
                                                    $rst.RDP = $false
                                                    Write-Verbose "Error testing RDP: $_"
                                                }
                                            }
		                                Write-verbose "RDP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                        #########ping
	                                    if(test-connection $ip -count 2 -Quiet)
	                                    {
	                                        Write-verbose "PING:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                $rst.ping = $true
			    
                                            if($WSMAN -or $All)
                                            {
                                                try{############wsman
				                                    Test-WSMan $ip -ErrorAction stop | Out-Null
				                                    $rst.WSMAN = $true
				                                }
			                                    catch
				                                {
                                                    $rst.WSMAN = $false
                                                    Write-Verbose "Error testing WSMAN: $_"
                                                }
				                                Write-verbose "WSMAN:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    if($rst.WSMAN -and $credssp) ########### credssp
			                                    {
				                                    try{
					                                    Test-WSMan $ip -Authentication Credssp -Credential $cred -ErrorAction stop
					                                    $rst.CredSSP = $true
					                                }
				                                    catch
					                                {
                                                        $rst.CredSSP = $false
                                                        Write-Verbose "Error testing CredSSP: $_"
                                                    }
				                                    Write-verbose "CredSSP:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
			                                    }
                                            }
                                            if($RemoteReg -or $All)
                                            {
			                                    try ########remote reg
			                                    {
				                                    [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ip) | Out-Null
				                                    $rst.remotereg = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.remotereg = $false
                                                    Write-Verbose "Error testing RemoteRegistry: $_"
                                                }
			                                    Write-verbose "remote reg:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($RPC -or $All)
                                            {
			                                    try ######### wmi
			                                    {	
				                                    $w = [wmi] ''
				                                    $w.psbase.options.timeout = 15000000
				                                    $w.path = "\\$Name\root\cimv2:Win32_ComputerSystem.Name='$Name'"
				                                    $w | select none | Out-Null
				                                    $rst.RPC = $true
			                                    }
			                                    catch
				                                {
                                                    $rst.rpc = $false
                                                    Write-Verbose "Error testing WMI/RPC: $_"
                                                }
			                                    Write-verbose "WMI/RPC:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"
                                            }
                                            if($SMB -or $All)
                                            {

                                                #Use set location and resulting errors.  push and pop current location
                    	                        try ######### C$
			                                    {	
                                                    $path = "\\$name\c$"
				                                    Push-Location -Path $path -ErrorAction stop
				                                    $rst.SMB = $true
                                                    Pop-Location
			                                    }
			                                    catch
				                                {
                                                    $rst.SMB = $false
                                                    Write-Verbose "Error testing SMB: $_"
                                                }
			                                    Write-verbose "SMB:  $((New-TimeSpan $dt ($dt = get-date)).totalseconds)"

                                            }
	                                    }
		                                else
		                                {
			                                $rst.ping = $false
			                                $rst.wsman = $false
			                                $rst.credssp = $false
			                                $rst.remotereg = $false
			                                $rst.rpc = $false
                                            $rst.smb = $false
		                                }
		                                $results += $rst	
	                                }
                                }
	                            Write-Verbose "Time for $($Name): $((New-TimeSpan $cdt ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                }
                            }
                            end
                            {
	                            Write-Verbose "Time for all: $((New-TimeSpan $total ($dt)).totalseconds)"
	                            Write-Verbose "----------------------------"
                                return $results
                            }
                        }
                    
                    #Build up parameters for Test-Server and run it
                        $TestServerParams = @{
                            ComputerName = $Computer
                            ErrorAction = "Stop"
                        }

                        if($detail -eq "*"){
                            $detail = "WSMan","RemoteReg","RPC","RDP","SMB" 
                        }

                        $detail | Select -Unique | Foreach-Object { $TestServerParams.add($_,$True) }
                        Test-Server @TestServerParams | Select -Property $( "Name", "IP", "Domain", "Ping" + $detail )
                }
                Catch
                {
                    Write-Warning "Error with Test-Server: $_"
                }
            }
            #We just want ping output
            else
            {
                Try
                {
                    #Pick out a few properties, add a status label.  If quiet output, just return the address
                    $result = $null
                    if( $result = @( Test-Connection -ComputerName $computer -Count 2 -erroraction Stop ) )
                    {
                        $Output = $result | Select -first 1 -Property Address,
                                                                      IPV4Address,
                                                                      IPV6Address,
                                                                      ResponseTime,
                                                                      @{ label = "STATUS"; expression = {"Responding"} }

                        if( $quiet )
                        {
                            $Output.address
                        }
                        else
                        {
                            $Output
                        }
                    }
                }
                Catch
                {
                    if(-not $quiet)
                    {
                        #Ping failed.  I'm likely making inappropriate assumptions here, let me know if this is the case : )
                        if($_ -match "No such host is known")
                        {
                            $status = "Unknown host"
                        }
                        elseif($_ -match "Error due to lack of resources")
                        {
                            $status = "No Response"
                        }
                        else
                        {
                            $status = "Error: $_"
                        }

                        "" | Select -Property @{ label = "Address"; expression = {$computer} },
                                              IPV4Address,
                                              IPV6Address,
                                              ResponseTime,
                                              @{ label = "STATUS"; expression = {$status} }
                    }
                }
            }
        }
    }
}
