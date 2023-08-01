function Install-NetspiAgent {

    <#
        .SYNOPSIS
        This function can be used to install the NetSPI BAS Agent as a scheduled task.
	    It will do the following:	    
	    1. Verify the process and system meets the minimum requirements for the script.    
	    2. Create and execute a scheduled task that will run the agent from a provided location as SYSTEM.
	    3. The task will start the task upon reboot.	    
	    4. The script will also verify that the process has started.
	    
            .PARAMETER AgentPath
            Full path to the target agent executable.
            .PARAMETER TaskName
            Task name to be used.          
            .EXAMPLE
            Install-NetspiAgent -AgentPath "C:\agent\NetSPI-BAS-Agent.exe"
            Install-NetspiAgent -AgentPath "C:\agent\NetSPI-BAS-Agent.exe" -TaskName "NetSPI-BAS-Agent"
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
            Version: 1.0
    #>

        param (
        [Parameter(Mandatory = $true,
        HelpMessage = 'Full path to the target agent executable.')]
        [string]$AgentPath = "",
        [Parameter(Mandatory = $false,
        HelpMessage = 'Task name to be used. ')]
        [string]$TaskName = "NetSPI-BAS-Agent"
    )

    begin {

        # Simple banner
        Write-Output ""
        Write-Output "######################################"
        Write-Output "NetSPI - www.netspi.com"
        Write-Output "Breach and Attack Simluation (BAS)"
        Write-Output "Agent Installation Script"
        Write-Output "######################################"
        Write-Output ""

        Write-Output " Verifying Script Requirements"

        # Check for admin privileges
        function Test-Administrator {
            $isElevated = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544"
            return $isElevated
        }

        $isAdmin = Test-Administrator
        if ($isAdmin) {
            Write-Output " - Verified process has administrative privileges"
        } else {
            Write-Output "This process is not running with administrative privileges. Please relaunch PowerShell with the correct privileges."
            break
        }

        # Check PowerShell version
        $minimumVersion = [Version]"4.0"
        $psVersion = $PSVersionTable.PSVersion

        if ($psVersion -ge $minimumVersion) {
            Write-Output " - Verified PowerShell version ($psVersion) meets min requirements"
        } else {
            Write-Output " - PowerShell version is older than $minimumVersion. Please run with $minimumVersion or later."
            break
        }

        # Bypass Execution Policy
        Set-ExecutionPolicy Bypass -Scope Process -Force
        If((Get-ExecutionPolicy -Scope Process) -like "Bypass"){
            Write-Output " - Verified PowerShell execution policy bypass"
        }else{
            Write-Output " - PowerShell execution policy bypass failed"
            break
        }

        # Test path to agent executable
        if((Test-Path "$AgentPath")){
            Write-Output " - Verified target file exists: $AgentPath "
        }else{
            Write-Output " - The target file does not exist: $AgentPath "
            break
        }

        # Get exe name
        $AgentPathExe = (Get-Item $AgentPath).Name
    }

    process{

        # Set Target Executable
        $ExeTarget = "c:\agent\NetSPI-BAS-Agent.exe"  

        # Set Task Trigger
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # Set Task Action
        $action = New-ScheduledTaskAction -Execute "$AgentPath"  

        # Register Task
        Write-Output " "
        Write-Output " Creating scheduled task named '$TaskName'"
        Write-Output " $AgentPath"
        $null = Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -User "SYSTEM" -RunLevel Highest -Force

        # Run Task
        Write-Output " "
        Write-Output " Starting scheduled task named '$TaskName'"
        Start-ScheduledTask -TaskName $TaskName
        Write-Output " - Executed"

        # Waiting 5 seconds
        Write-Output " - Waiting 5 seconds"
        sleep 5

        # Check for running task
        Write-Output " "
        Write-Output " Checking for process '$AgentPathExe'"
        $SanityCheck = Get-Process | Where path -like "*$AgentPathExe*"

        If ($SanityCheck.count -eq 0){
            Write-Output " Verified agent failed to lauch."
            break
        }else{
            Write-Output " - Verified agent successfully launched."
            Write-Output " - You should see it checking in."
        }
    }

    end {
    }

}

function Remove-NetspiAgent {

    <#
        .SYNOPSIS
        This function can be used to uninstall the NetSPI BAS Agent as a scheduled task.
	    It will do the following:	    
	    1. Verify script requirements.  
	    2. Remove a schedule task based on the provided name.
	    
            .PARAMETER TaskName
            Task name to be used if it is not the default value "NetSPI-BAS-Agent".          
            .EXAMPLE
            Remove-NetspiAgent -TaskName "NetSPI-BAS-Agent"
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
            Version: 1.0
    #>

        param (
        [Parameter(Mandatory = $false,
        HelpMessage = 'Name of task to be removed. ')]
        [string]$TaskName = "NetSPI-BAS-Agent"
    )

    begin {

        # Simple banner
        Write-Output ""
        Write-Output "######################################"
        Write-Output "NetSPI - www.netspi.com"
        Write-Output "Breach and Attack Simluation (BAS)"
        Write-Output "Agent Removal Script"
        Write-Output "######################################"
        Write-Output ""

        Write-Output " Verifying Script Requirements"

        # Check for admin privileges
        function Test-Administrator {
            $isElevated = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups -match "S-1-5-32-544"
            return $isElevated
        }

        $isAdmin = Test-Administrator
        if ($isAdmin) {
            Write-Output " - Verified process has administrative privileges"
        } else {
            Write-Output "This process is not running with administrative privileges. Please relaunch PowerShell with the correct privileges."
            break
        }

        # Check PowerShell version
        $minimumVersion = [Version]"4.0"
        $psVersion = $PSVersionTable.PSVersion

        if ($psVersion -ge $minimumVersion) {
            Write-Output " - Verified PowerShell version ($psVersion) meets min requirements"
        } else {
            Write-Output " - PowerShell version is older than $minimumVersion. Please run with $minimumVersion or later."
            break
        }

        # Bypass Execution Policy
        Set-ExecutionPolicy Bypass -Scope Process -Force
        If((Get-ExecutionPolicy -Scope Process) -like "Bypass"){
            Write-Output " - Verified PowerShell execution policy bypass"
        }else{
            Write-Output " - PowerShell execution policy bypass failed"
            break
        }
    }

    process{

        # Get executable path from task     
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

        if ($task) {
            $actionPath = $task.Actions | Select Execute -ExpandProperty Execute
            Write-Output " - Obtained executable path"
            Write-Output "   $actionPath" 
            $RootFile = (Get-Item "$actionPath").Name
            $RootPath = $actionPath.Replace("$RootFile","")
        } else {
            Write-Output "Scheduled task '$taskName' not found."
            break
        }


        # Stop the schedule task
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            try {
                Stop-ScheduledTask -TaskName $taskName 

                # Check if the task is no longer running
                $isRunning = (Get-ScheduledTask -TaskName $taskName).State -eq "Running"
                if (-Not $isRunning) {
                    Write-Output " - Scheduled task '$taskName' has been stopped."
                } else {
                    Write-Output " - Failed to stop the scheduled task '$taskName'."
                }
            } catch {
                Write-Output "Error occurred while trying to stop the scheduled task: $_"
            }
        } else {
            Write-Output " - Scheduled task '$taskName' not found."
            break
        }

        # Remove scheduled task
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Output " - Scheduled task '$TaskName' has been removed."
        } else {
            Write-Output " - Scheduled task '$TaskName' not found."
            break
        }
        
        # Stop related processes
        $TargetProcesses = Get-Process | where path -like "$actionPath"
        $TargetProcesses | 
        foreach {
            $TargetId = $_.Id
            Stop-Process -Id $TargetId -Force
        }
        
        $TargetProcesses = Get-Process | where path -like "$actionPath"
        if(($TargetProcesses.count) -eq 0){
             Write-Output " - Confirmed processes were terminated."
        }else{
             Write-Output " - Unable to terminate related processes."
        }

        # Remove exe
        if (Test-Path $actionPath) {
            try {
                # Attempt to remove the file
                Remove-Item $actionPath -Force

                # Check if the file was successfully removed
                if (-Not (Test-Path $actionPath)) {
                    Write-Output " - File removed successfully: $actionPath"
                } else {
                    Write-Output " - Failed to remove the file: $actionPath"
                }
            } catch {
                Write-Output " - Error occurred while trying to remove the file: $_"
            }
        } else {
            Write-Output " - File not found: $actionPath"
        }

        # Remove config
        $RootPathFull =  "$RootPath" + "bas_agent_profile*.json"
        if (Test-Path $RootPathFull ) {
            try {
                # Attempt to remove the file                
                Remove-Item "$RootPathFull" -Force

                # Check if the file was successfully removed
                if (-Not (Test-Path $RootPathFull)) {
                    Write-Output " - File removed successfully: $RootPathFull"
                } else {
                    Write-Output " - Failed to remove the file: $RootPathFull"
                }
            } catch {
                Write-Output " - Error occurred while trying to remove the file: $_"
            }
        } else {
            Write-Output " - File not found: $RootPathFull"
        }

	Write-Output ""
        Write-Output "PLEASE NOTE:"
        Write-Output "YOU MAY HAVE TO SHUTDOWN THE IN MEMORY AGENT THROUGH THE AGENTS DASHBOARD."
    }

    end {
    }

}

