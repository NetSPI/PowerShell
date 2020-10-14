<#
    Script: Get-SSLCertInfo-Scan.psm1

    Version: 1.8

    Author: Scott Sutherland (@_nullbind), NetSPI
    References: This was based on work by Rob VandenBrink.
    References: https://isc.sans.edu/forums/diary/Assessing+Remote+Certificates+with+Powershell/20645/ 

    Description:  This script accepts IP/Port combinations and can be used to read information such as 
                  subject, name, and issuerfrom remote SSL certificates. See examples for more information.                                     
    Examples:

    # Target specific IP and port
    Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -Port 443

    # Target specific IP Range and port options
    Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -cidr 24 -Port 443
    Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -mask 255.255.255.0 -Port 443
    Get-SSLCertInfo-Scan -Verbose -Start 192.168.1 -End 192.168.1.150 -Port 443

    # Target hostname and port
    Get-SSLCertInfo-Scan -Verbose -IPAddress domain.com -Port 443

    # Target a list of IP:Port from file, one per line; Display full records
    Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt 

    # Target a list of IP:Port from file, one per line; Display a list of domains discovered.
    Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -OnlyDomainList
    
    # Target a list of IP:Port from file, one per line; Look up associated arin info.
    Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -ArinLookup   

    # Target a list of IP:Port from pipeline
    "127.0.0.1:50" | Get-SSLCertInfo-Scan -Verbose 

    # Target a list of IP:Port from file, one per line; Display a list of domains discovered. Show potential
    # Active Directory domains in verbose output based on number of ".".
    Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -OnlyDomainList -ShowAdDomains

    # Target all parameters, pipeline, and file inputs.  Store the results and display them
    $Results = "127.0.0.1:50","127.0.0.2:50", | Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -IPAddress 127.0.0.3 -Port 443
    $Results
    $Results | Export-CSV -NoTypeInformation output.csv
    $Results | Out-GridView

    # Todo    
    Add runspace threading
    Add nmap importer
    Add nessus importer
#>

function Get-SSLCertInfo-Scan {

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="File containing URLs/IP and ports IP:Port.")]
        [string]$InputFile,
        [Parameter(Mandatory=$false,
        HelpMessage="Only display list of uniq domains.")]
        [switch]$OnlyDomainList,
        [Parameter(Mandatory=$false,
        HelpMessage="List potential Active Directory domains.")]
        [switch]$ShowAdDomains, 
        [Parameter(Mandatory=$false,
        HelpMessage="Look up ip address owner.")]
        [switch]$ArinLookup,
        [Parameter(Mandatory=$false,
        HelpMessage="IP Address.")]
        [string]$IPAddress,
        [Parameter(Mandatory=$false,
        HelpMessage="Used with the ipaddress parameter to define a subnet to be scanned.")]
        [string]$Cidr,
        [Parameter(Mandatory=$false,
        HelpMessage="Used with the ipaddress parameter to define a subnet to be scanned.")]
        [string]$mask,
        [Parameter(Mandatory=$false,
        HelpMessage="Used to define first ip address in range.")]
        [string]$StartIp,
        [Parameter(Mandatory=$false,
        HelpMessage="Used to define end ip address in range.")]
        [string]$EndIp,
        [Parameter(Mandatory=$false,
        HelpMessage="TCP port.")]
        [string]$Port,
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="IP port combo IP:PORT.")]
        [string]$IPPort
    )

    Begin
    {
        Write-Verbose "Creating a list of targets"

        # Create output table
        $CertificateInfo = New-Object System.Data.DataTable
        $null = $CertificateInfo.Columns.Add("IpAddress")
        $null = $CertificateInfo.Columns.Add("Port")
        $null = $CertificateInfo.Columns.Add("Subject")
        $null = $CertificateInfo.Columns.Add("EffectiveDate")
        $null = $CertificateInfo.Columns.Add("ExpirationDate")
        $null = $CertificateInfo.Columns.Add("Issuser")
        $null = $CertificateInfo.Columns.Add("Verified")

        # Create targets table
        $Targets = New-Object System.Data.DataTable
        $null = $targets.Columns.Add("IPAddress")
        $null = $targets.Columns.Add("Port")

        # If port provided in parameter
        if(-not $TargetPort -and $Port){
            $TargetPort = $Port
        }                      

        # If port not provided in file, and none provided in parameter - default port :)
        if(-not $TargetPort){
            $TargetPort = "443"
        }

        # Process single target with defined port
        if($IPAddress -and $Port -and -not $cidr -and -not $mask)
        {
            # Add target to list
            Write-Verbose " - Importing targets from parameters"   
            $targets.Rows.Add($IPAddress,$Port) | Out-Null  
        }

        # Process single target without defined port
        if($IPAddress -and -not $Port -and -not $cidr -and -not $mask)
        {
            # Add target to list
            $Port = "443"
            Write-Verbose " - Importing targets from parameters"   
            $targets.Rows.Add($IPAddress,$Port) | Out-Null  
        }

        # Process single IP:Port target 
        if($IPPort)
        {
            $Target = $IPPort -split(":")[0]  
            $TargetPort = $Target[1]   
            $TargetIP = $Target[0]                       

            # Add to targets list      
            Write-Verbose " - Importing targets from parameters - alt format"     
            $targets.Rows.Add($TargetIp,$TargetPort) | Out-Null   
        }

        # Process IP range - CIDR
        if($IPAddress -and $Cidr){
            Write-Verbose " - Importing IP range cidr - $IPAddress/$cidr on $TargetPort"
            Get-IPrange -ip $IPAddress -cidr $Cidr|
            ForEach-Object{
                $targets.Rows.Add($_,$TargetPort) | Out-Null  
            }
        }

        # Process IP range - Mask
        if($IPAddress -and $mask){
            Write-Verbose " - Importing IP range mask $IPAddress - $mask on $TargetPort"
            Get-IPrange -ip $IPAddress -mask $mask|
            ForEach-Object{
                $targets.Rows.Add($_,$TargetPort) | Out-Null  
            }
        }

        # Process IP range - Start/End
        if($StartIp -and $EndIp){
            Write-Verbose " - Importing IP range $startip - $Endip on $TargetPort"
            Get-IPrange -start $StartIp -end $EndIp |
            ForEach-Object{
                $targets.Rows.Add($_,$TargetPort) | Out-Null  
            }
        }

        # Process a list of targets
        if($InputFile){

            # Get target list from file
            if(Test-Path -Path $InputFile){
            
                Write-Verbose " - Importing targets from $InputFile"
                $IpPortList = gc $InputFile                               
                $IpPortList |
                ForEach-Object {
                    $Target = $_ -split(":")[0]  
                    $TargetPort = $Target[1]   
                    $TargetIP = $Target[0] 

                    # If port provided in parameter
                    if(-not $TargetPort -and $Port){
                        $TargetPort = $Port
                    }                      

                    # If port not provided in file, and none provided in parameter - default port :)
                    if(-not $TargetPort){
                        $TargetPort = "443"
                    }
                    
                    # Add to targets list
                    $targets.Rows.Add($TargetIp,$TargetPort) | Out-Null                  
                }
            }else{
                Write-Verbose " - File path is invalid."
            }           
        }
    }

    Process
    {
        # Add targets from the pipeline
        if($_){

            Write-Verbose " - Importing targets from pipeline"

            # Get target list from pipeline
            $Target = $_ -split(":")[0]  
            $TargetIp = $Target[1]   
            $TargetPort = $Target[0]   
                    
            # Add to targets list
            $targets.Rows.Add($TargetIp,$TargetPort) | Out-Null   
        }
    }

    End
    {

        # ------------------------------
        # Scrape cert info from targets
        # ------------------------------
        Write-Verbose "Grabbing certificate information"
        $DraftResults = $targets | 
        ForEach-Object {
            $CurrentIp = $_.IpAddress
            $CurrentPort = $_.Port            
            Get-CertInfo -IPAddress $CurrentIp -Port $CurrentPort -ErrorAction SilentlyContinue  
        } 
        
        # ------------------------------
        # Get unique list of domains
        # ------------------------------
        $AltDomainList = $DraftResults | where SubjectAltName -notlike "" | Select-Object SubjectAltName -ExpandProperty SubjectAltName                   
        $OrgDomainList = $DraftResults | where SubjectDomain -notlike "" | Select-Object SubjectDomain -ExpandProperty SubjectDomain      
        $DomainList = $AltDomainList+$OrgDomainList | Select-Object @{Name="DomainName";Expression={$_}} | Sort-Object DomainName -Unique             
        $DomainCount = $DomainList.count
        Write-Verbose "$DomainCount unique domains found."


        # ------------------------------
        # Resolve arin if asked
        # ------------------------------  
        if($ArinLookup -and (-not $OnlyDomainList)){
            Write-Verbose "Processing arin lookups"            
            $DraftResults | Where-Object SubjectDomain -NotLike "" |
            foreach {
                $rdomain = $_.SubjectDomain
                $rsubdomain = $_.SubjectAltName
                $rip = $_.ipaddress
                $rport = $_.port
                Write-Verbose "  - Processing arin lookups - $rip ($rdomain - $rsubdomain)"                
                Invoke-Arin-Lookup -Verbose -IpAddress $rip -IpPort $_.port -Domain $rdomain -SubDomain $rsubdomain -Subject $_.Subject -SubjectCountry $_.SubjectCountry -SubjectState $_.SubjectState -SubjectCity $_.SubjectCity -SubjectOrganization $_.SubjectOrganization -SubjectOU $_.SubjectOU -Issuer $_.Issuer -ExpirationDate $_.ExpirationDate -EffectiveDate $_.EffectiveDate -Verified $_.Verified -thumbprint $_.thumbprint -ErrorAction SilentlyContinue
            }           
        }
         
        # Display Results
        If($OnlyDomainList){                
            $DomainList            
        }else{
            if(-not $ArinLookup){
                $DraftResults | Sort-Object SubjectDomain,SubjectAltName -Unique       
            }
        }

        # ------------------------------
        # Check for potential ad domains
        # ------------------------------
        if($ShowAdDomains){
            
            # All domains with > 2 ".", filter out www, drop host name, uniuque display
            Write-Verbose "Checking for potential Active Directory domains."
            $PotentialAdDomains = New-Object System.Data.DataTable 
            $PotentialAdDomains.Columns.add("DomainName") | Out-Null                
            $DomainList | 
            ForEach-Object {
                #$CheckDomain = "hostname.subdomain.domain.com"
                $CheckDomain = $_.DomainName
                $CheckDomainArray = $CheckDomain.Split(".")
                $CheckDomainNum = $CheckDomainArray.GetUpperBound(0);
                if(($CheckDomainNum -gt 2) -and ($CheckDomain -notlike "*www.*")){                

                    # Grab the potential ad domain by dropping the hostname
                    #$PotentialAdDomains += [string]($CheckDomainArray[1..$CheckDomainNum] -join("."))
                    $PotentialAdDomains += [string]($CheckDomainArray[1..$CheckDomainNum] -join("."))
                }
            }

            # Display final list  
            $PotentialAdDomainsUnique = $PotentialAdDomains | Select-Object -Unique          
            $AdCount = $PotentialAdDomainsUnique.count
            Write-Verbose "$AdCount potential Active Directory domains were found."
            $PotentialAdDomainsUnique | foreach {write-verbose "- $_"}   
            
            # Write log
            if($ADOutputFile){
                $PotentialAdDomainsUnique | Out-File $ADOutputFile
            }
        }          
    }
}

function Get-CertInfo
{
    [CmdletBinding()]
    Param (
            [string]$IPAddress,
            [Parameter(Mandatory=$false,
            HelpMessage="TCP port.")]
            [string]$Port
    )

    write-verbose " - Grabbing certificate info from $IPAddress on $port"

    # Create connection to server
    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
    $TcpSocket = New-Object Net.Sockets.TcpClient($IPAddress,$Port)
    $TcpSocket.ReceiveTimeout = 5000;    

    # Establish stream
    $tcpstream = $TcpSocket.GetStream()
    $Callback = {param($sender,$cert,$chain,$errors) return $true}
    $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $True, $Callback)
    $SSLStream.AuthenticateAsClient($IPAddress)    
    
    # Grab cert information
    $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)

    # Clean up
    $SSLStream.Dispose()
    $TCPClient.Dispose()

    $SubjectArray = $Certificate.GetName() -split(",")
    $SubjectArray | 
    ForEach-Object{
        
        $item = $_.ToString().Trim()
        $itemParts = $item -split("=")
        
        # Set country
        if($itemParts[0] -like "C"){        
            $Country = $itemParts[1] 
        }

        # Set state
        if(($itemParts[0] -like "S") -or ($itemParts[0] -like "ST")){        
            $State = $itemParts[1] 
        }

        # Set city
        if($itemParts[0] -like "L"){        
            $City = $itemParts[1]
        }

        # Set Oranization
        if($itemParts[0] -like "O"){        
            $Organization = $itemParts[1] 
        }

        # Set Oranization Unit
        if($itemParts[0] -like "OU"){           
            $OranizationalUnit = $itemParts[1]             
        }

        # Set Domain
        if($itemParts[0] -like "CN"){        
            $Domain = $itemParts[1] 
        }
    }

    # Get Alternative Domain List    
    if($Certificate.DnsNameList){
        $Certificate.DnsNameList | 
        ForEach-Object{            

            [string]$AltDomain = $_[0];
            $CertInfo = New-Object PSObject
            $CertInfo | add-member Noteproperty IpAddress $IPAddress;
            $CertInfo | add-member Noteproperty Port $Port;
            $CertInfo | add-member Noteproperty Subject $Certificate.GetName();
            $CertInfo | add-member Noteproperty SubjectCountry $Country;
            $CertInfo | add-member Noteproperty SubjectState $State;
            $CertInfo | add-member Noteproperty SubjectCity $City;
            $CertInfo | add-member Noteproperty SubjectOrganization $Organization;
            $CertInfo | add-member Noteproperty SubjectOU $OranizationalUnit;
            $CertInfo | add-member Noteproperty SubjectDomain $Domain;
            $CertInfo | add-member Noteproperty SubjectAltName $AltDomain;
            $CertInfo | add-member Noteproperty Issuer $Certificate.GetIssuerName();    
            $CertInfo | add-member Noteproperty ExpirationDate $Certificate.GetEffectiveDateString();
            $CertInfo | add-member Noteproperty EffectiveDate $Certificate.GetExpirationDateString();        
            $CertInfo | add-member Noteproperty Verified $Certificate.Verify();
            $CertInfo | add-member Noteproperty thumbprint $Certificate.Thumbprint;
            $CertInfo
        }
    }else{

        $CertInfo = New-Object PSObject
        $CertInfo | add-member Noteproperty IpAddress $IPAddress;
        $CertInfo | add-member Noteproperty Port $Port;
        $CertInfo | add-member Noteproperty Subject $Certificate.GetName();
        $CertInfo | add-member Noteproperty SubjectCountry $Country;
        $CertInfo | add-member Noteproperty SubjectState $State;
        $CertInfo | add-member Noteproperty SubjectCity $City;
        $CertInfo | add-member Noteproperty SubjectOrganization $Organization;
        $CertInfo | add-member Noteproperty SubjectOU $OranizationalUnit;
        $CertInfo | add-member Noteproperty SubjectDomain $Domain;
        $CertInfo | add-member Noteproperty SubjectDomainAlt "";
        $CertInfo | add-member Noteproperty Issuer $Certificate.GetIssuerName();    
        $CertInfo | add-member Noteproperty ExpirationDate $Certificate.GetEffectiveDateString();
        $CertInfo | add-member Noteproperty EffectiveDate $Certificate.GetExpirationDateString();        
        $CertInfo | add-member Noteproperty Verified $Certificate.Verify();
        $CertInfo | add-member Noteproperty thumbprint $Certificate.Thumbprint;
        $CertInfo
    }
}

function Invoke-Arin-Lookup{ 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="The IP Address to lookup.")]
        [string]$IpAddress,
        [Parameter(Mandatory=$false,
        HelpMessage="port.")]
        [string]$IpPort,
        [Parameter(Mandatory=$false,
        HelpMessage="Original domain.")]
        [string]$Domain,
        [Parameter(Mandatory=$false,
        HelpMessage="Sub domain.")]
        [string]$SubDomain,
        [Parameter(Mandatory=$false,
        HelpMessage="subjectCountry.")]
        [string]$Subject,
        [Parameter(Mandatory=$false,
        HelpMessage="subjectCountry.")]
        [string]$SubjectCountry,
        [Parameter(Mandatory=$false,
        HelpMessage="SubjectState.")]
        [string]$SubjectState,
        [Parameter(Mandatory=$false,
        HelpMessage="SubjectCity.")]
        [string]$SubjectCity,
        [Parameter(Mandatory=$false,
        HelpMessage="SubjectOrganization.")]
        [string]$SubjectOrganization,
        [Parameter(Mandatory=$false,
        HelpMessage="SubjectOU.")]
        [string]$SubjectOU,
        [Parameter(Mandatory=$false,
        HelpMessage="Issuer.")]
        [string]$Issuer,
        [Parameter(Mandatory=$false,
        HelpMessage="ExpirationDate.")]
        [string]$ExpirationDate,
        [Parameter(Mandatory=$false,
        HelpMessage="EffectiveDate.")]
        [string]$EffectiveDate,
        [Parameter(Mandatory=$false,
        HelpMessage="Verified.")]
        [string]$Verified,
        [Parameter(Mandatory=$false,
        HelpMessage="thumbprint.")]
        [string]$thumbprint
    )

    Begin
    {      
        # IP info table
        $TblIPInfo = new-object System.Data.DataTable
        $TblIPInfo.Columns.Add("Domain") | Out-Null
        $TblIPInfo.Columns.Add("Subdomain") | Out-Null
        $TblIPInfo.Columns.Add("IpPort") | Out-Null
        $TblIPInfo.Columns.Add("IpAddress") | Out-Null
        $TblIPInfo.Columns.Add("IpOwner") | Out-Null
        $TblIPInfo.Columns.Add("IpStartRange") | Out-Null
        $TblIPInfo.Columns.Add("IpEndRange") | Out-Null
        $TblIPInfo.Columns.Add("IpCountry") | Out-Null
        $TblIPInfo.Columns.Add("IpState") | Out-Null
        $TblIPInfo.Columns.Add("IpCity") | Out-Null
        $TblIPInfo.Columns.Add("IpZip") | Out-Null
        $TblIPInfo.Columns.Add("IpISP") | Out-Null 
        $TblIPInfo.Columns.Add("CertSubject") | Out-Null
        $TblIPInfo.Columns.Add("CertSubjectCountry") | Out-Null
        $TblIPInfo.Columns.Add("CertSubjectState") | Out-Null
        $TblIPInfo.Columns.Add("CertSubjectCity") | Out-Null
        $TblIPInfo.Columns.Add("CertSubjectOrganization") | Out-Null
        $TblIPInfo.Columns.Add("CertSubjectOU") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuer") | Out-Null
        $TblIPInfo.Columns.Add("CertExpirationDate") | Out-Null
        $TblIPInfo.Columns.Add("CertEffectiveDate") | Out-Null
        $TblIPInfo.Columns.Add("CertVerified") | Out-Null
        $TblIPInfo.Columns.Add("Certthumbprint") | Out-Null

        # Lookup source IP owner 
        if($IpAddress -notlike ""){

            try{
                [IpAddress]$IpAddress | Out-Null
                $IP = "yes"
            }catch{
                $IP = "no"
                $IpAddress = Resolve-DnsName -DnsOnly netspi.com | select ipaddress -ExpandProperty ipaddress        
            }

            # Send whois request to arin via restful api
            $targetip = $IpAddress

            # arin lookup
            $web = new-object system.net.webclient
            [xml]$results = $web.DownloadString("http://whois.arin.net/rest/ip/$targetip")

            # Send location query to http://ip-api.com via xml api
            if ($IpAddress){
                $web2 = new-object system.net.webclient
                [xml]$results2 = $web2.DownloadString("http://ip-api.com/xml/$targetip")
            }            

            # Parse data from responses    
            $IpOwner = $results.net.name 
            $IpStart = $results.net.startAddress
            $IpEnd = $results.net.endaddress  
            $IpCountry = $results2.query.country.'#cdata-section'
            $IpState = $results2.query.region.'#cdata-section'
            $IpCity = $results2.query.city.'#cdata-section'            
            $IpZip = $results2.query.zip.'#cdata-section'
            $IpISP = $results2.query.isp.'#cdata-section'

            # Put results in the data table   
            $TblIPInfo.Rows.Add(
                "$Domain",
                "$SubDomain",
                "$IpPort",
                "$IpAddress",
                "$IpOwner",
                "$IpStart",
                "$IpEnd",
                "$IpCountry",
                "$IpState",
                "$IpCity",
                "$IpZip",
                "$IpISP",
                "$Subject",
                "$SubjectCountry",  
                "$SubjectState",
                "$SubjectCity",
                "$SubjectOrganization",
                "$SubjectOU",
                "$Issuer",
                "$ExpirationDate",
                "$EffectiveDate",
                "$Verified",
                "$thumbprint" ) | Out-Null           
        }else{
            # Put results in the data table   
            $TblIPInfo.Rows.Add(
                "$Domain",
                "$SubDomain",
                "$IpPort",
                "$IpAddress",
                "$IpOwner",
                "$IpStart",
                "$IpEnd",
                "$IpCountry",
                "$IpState",
                "$IpCity",
                "$IpZip",
                "$IpISP",
                "$Subject",
                "$SubjectCountry",  
                "$SubjectState",
                "$SubjectCity",
                "$SubjectOrganization",
                "$SubjectOU",
                "$Issuer",
                "$ExpirationDate",
                "$EffectiveDate",
                "$Verified",
                "$thumbprint" ) | Out-Null 
        }

        # Display results
        $TblIPInfo                   
    }

    End
    {
    }
}

# -------------------------------------------
# Function:  Get-IPrange
# -------------------------------------------
# Author: BarryCWT
# Reference: https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b
function Get-IPrange
            {
                <# 
                  .SYNOPSIS  
                    Get the IP addresses in a range 
                  .EXAMPLE 
                   Get-IPrange -start 192.168.8.2 -end 192.168.8.20 
                  .EXAMPLE 
                   Get-IPrange -ip 192.168.8.2 -mask 255.255.255.0 
                  .EXAMPLE 
                   Get-IPrange -ip 192.168.8.3 -cidr 24 
                #> 
 
                param 
                ( 
                  [string]$start, 
                  [string]$end, 
                  [string]$ip, 
                  [string]$mask, 
                  [int]$cidr 
                ) 
 
                function IP-toINT64 () { 
                  param ($ip) 
 
                  $octets = $ip.split(".") 
                  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
                } 
 
                function INT64-toIP() { 
                  param ([int64]$int) 

                  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
                } 
 
                if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
                if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
                if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)} 
                if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
                if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
                if ($ip) { 
                  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
                  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
                } else { 
                  $startaddr = IP-toINT64 -ip $start 
                  $endaddr = IP-toINT64 -ip $end 
                } 
 
                for ($i = $startaddr; $i -le $endaddr; $i++) 
                { 
                  INT64-toIP -int $i 
                }
            }
