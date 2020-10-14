# -----------------------------------------
# Function: Get-BadPrivilege
# -----------------------------------------
# With local administrator privileges, this script uses PoshPrivilege to list all user right/privilege assignments.
# It then filters for known dangerous privileges based on https://twitter.com/vysecurity/status/1315272197959749635.
# Requires: https://github.com/proxb/PoshPrivilege
# Wrapper Author: Scott Sutherland, @_nullbind NetSPI 2020
Function Get-BadPrivilege
{

    # Check if Get-Privilege has bee loaded
    $CheckFunc = Test-Path Function:\Get-Privilege
    If(-not $CheckFunc){
        Write-Output "The Get-Privilege function does not appear to be available."
        Write-Output "It can be downloaded from https://github.com/proxb/PoshPrivilege."
        Write-Output "Aborting run."
        break
    }

    # Check if the current user is an administrator
    $CheckAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If(-not $CheckAdmin){
        Write-Output "This script must be run as a local adminsitrator."  
        Write-Output "Aborting run."  
        break
    }

    # Create a table of known high risk rights/privileges
    $BadPrivileges = New-Object System.Collections.Arraylist
    $null = $BadPrivileges.Add("SeImpersonatePrivilege")
    $null = $BadPrivileges.Add("SeAssignPrimaryPrivilege")
    $null = $BadPrivileges.Add("SeTcbPrivilege")
    $null = $BadPrivileges.Add("SeBackupPrivilege")
    $null = $BadPrivileges.Add("SeRestorePrivilege")
    $null = $BadPrivileges.Add("SeCreateTokenPrivilege")
    $null = $BadPrivileges.Add("SeLoadDriverPrivilege")
    $null = $BadPrivileges.Add("SeTakeOwnershipPrivilege")
    $null = $BadPrivileges.Add("SeDebugPrivilege")

    # Iterate through identified right/privilege assignments
    Get-Privilege | 
    ForEach-Object{

        # Get privilege information
        $MyComputerName     = $_.ComputerName
        $MyPrivilege        = $_.Privilege
        $MyDescription      = $_.Description
        $MyAffectedAccounts = $_.Accounts  

        # Check if the privilege is high risk
        $BadPrivileges | 
        ForEach-Object{                                   
            if ($_ -like "$MyPrivilege*")
            {          
                $MyRiskStatus = "Yes"
            }else{
                $MyRiskStatus = "No"
            }
        }

        # Parse affected accounts
        $MyAffectedAccounts | 
        ForEach-Object{

            $myObject = [PSCustomObject]@{
                ComputerName     = [string]$MyComputerName
                Privilege        = [string]$MyPrivilege
                HighRisk         = [string]$MyRiskStatus
                Description      = [string]$MyDescription
                User             = [string]$_           
            }  
        
            $myObject                    
        }        
    }
}
