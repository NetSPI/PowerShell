# Author: Scott Sutherland, @_nullbind, NetSPI
Function Send-ProtocolHandlerEmailLinks
{
 <#
            .SYNOPSIS
            The script can be used to enumerate local protocol handlers and create sample emails
            contain links to the handlers.  It is intended to be used for testing email controls
            that help prevent phishing.
            .PARAMETER TargetEmail
            Email address to send generated emails to.
            .PARAMETER OutPutFile
            File path where the list of protocol handlers with be written to.
            .PARAMETER Display only.
            Enumerate the protocol handlers and display them, but do not generate emails.
            .EXAMPLE
            PS C:\> Send-ProtocolHandlerEmailLinks -Verbose -TargetEmail target@email.com
            .EXAMPLE
            PS C:\> Send-ProtocolHandlerEmailLinks -Verbose -DisplayOnly
            .REFERENCES
            https://support.microsoft.com/en-us/help/310262/how-to-use-the-microsoft-outlook-object-library-to-send-an-html-format
            https://msrc-blog.microsoft.com/2008/12/09/ms08-075-reducing-attack-surface-by-turning-off-protocol-handlers/
            https://docs.microsoft.com/en-us/office/vba/api/outlook.application
            https://blogs.msdn.microsoft.com/noahc/2006/10/19/register-a-custom-url-protocol-handler/
            https://docs.microsoft.com/en-us/windows/win32/shell/app-registration
            https://docs.microsoft.com/en-us/windows/win32/shell/fa-intro
            https://www.vdoo.com/blog/exploiting-custom-protocol-handlers-in-windows
            https://zero.lol/2019-05-22-fun-with-uri-handlers/
 #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Set the target email address.')]
        [string]$TargetEmail,

        [Parameter(Mandatory = $false,
        HelpMessage = 'Output file path.')]
        [string]$OutPutFile = ".\protocolhandlers.csv",

        [Parameter(Mandatory = $false,
        HelpMessage = 'Only display the protocol handlers')]
        [switch]$DisplayOnly
    )

    Begin
    {
        # Create datatable for output
        $null = $DataTable = New-Object System.Data.DataTable;
        $null = $DataTable.Columns.Add("key");
        $null = $DataTable.Columns.Add("path");
    }
    
    Process
    {
        Write-Verbose "Enumerating protocol handlers"

        # Get protocol handlers
        foreach ($Key in Get-ChildItem Microsoft.PowerShell.Core\Registry::HKEY_CLASSES_ROOT)
        { 
            $Path = $Key.PSPath + '\shell\open\command';
            $HasURLProtocol = $Key.Property -contains 'URL Protocol';

            if(($HasURLProtocol) -and (Test-Path $Path)){
                $CommandKey = Get-Item $Path;
                $ProtBin = $CommandKey.GetValue("")
                $ProtKey = $Key.Name.SubString($Key.Name.IndexOf('\') + 1)
                $null = $DataTable.Rows.Add($ProtKey,$ProtBin)
            }
        }   

        # Display protocol handler count
        $PCount = $DataTable.Rows.Count 
        Write-Verbose "$PCount protocol handlers found"

        # Write list of handlers to a file
        $DataTable | Export-Csv -NoTypeInformation "$OutputFile"
        Write-Verbose "List of protocol handlers saved to $OutputFile"
        
        # Display list
        if($DisplayOnly){
            
            $DataTable
        }

        # Check if emails should / can be sent
        if((!$DisplayOnly) -and ($TargetEmail))
        {

            # Send emails
            Write-Output "$PCount emails are being sent to $TargetEmail"
            $DataTable | 
            Foreach {

                # Parse handler and associated executable.
                $Thekey = $_.Key
                $ThePath = $_.Path    
                Write-Verbose "Sending $Thekey"

                # Sending emails with protocol handler links to target email    
                $outlook = new-object -com outlook.application -Verbose:$False
                $ns = $outlook.GetNameSpace("MAPI");
                $mail = $outlook.CreateItem(0)
                $mail.subject = "Protocol Handler Test: $Thekey" 
                $Html = "<HTML>" + 
                        "<HEAD>" +
                        "<TITLE>$Thekey Test</TITLE>" +
                        "</HEAD>" +
                        "<BODY>" + 
                        "Key: $Thekey <br>" +
                        "Executable: $ThePath <br>" +                        
                        "<a href='$Thekey`://testin123'>Click Here Please</a><br>" +
                        "</BODY>" + 
                        "</HTML>";       
                $mail.HTMLbody = "$Html"    
                #$mail.body = "This is text only." 
                $mail.To = "$TargetEmail"
                $mail.Send()
            }
        }
    }

    End
    {
        # Nothing
    }
}

