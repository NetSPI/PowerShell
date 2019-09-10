<#
        File: Get-SSLCertInfo-Scan.psm1
        Author: Scott Sutherland (@_nullbind), NetSPI - 2019
        Version: 1.9
        Description: The functions in this module can be used to collect information from remote SSL certificates.
        License: BSD 3-Clause
#>

# -------------------------------------------
# Function:  Get-SSLCertInfo-Scan 
# -------------------------------------------
# Author: Scott Sutherland (@_nullbind), NetSPI 
function Get-SSLCertInfo-Scan 
{
 <#
            .SYNOPSIS
            This function accepts IP/Port combinations and can be used to read information such as 
            subject, name, and issuer from remote SSL certificates. See examples for more information.
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -Port 443
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -cidr 24 -Port 443
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -IPAddress 192.168.1 -mask 255.255.255.0 -Port 443
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -Start 192.168.1 -End 192.168.1.150 -Port 443
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -IPAddress domain.com -Port 443
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt 
            .EXAMPLE
            PS C:\> Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -Threads 25      
            .EXAMPLE
            PS C:\>  Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -OnlyDomainList
            .EXAMPLE
            PS C:\>  Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -ArinLookup  
            .EXAMPLE
            PS C:\>  "127.0.0.1:50" | Get-SSLCertInfo-Scan -Verbose
            PS C:\>  $Results = "127.0.0.1:50","127.0.0.2:50" | Get-SSLCertInfo-Scan -Verbose -InputFile C:\temp\list.txt -IPAddress 127.0.0.3 -Port 443
            $Results
            $Results | Out-Gridview
    #>
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
        HelpMessage="Number of threads to run at a time.")]
        [string]$Threads = 50,
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
        <#
        $DraftResults = $targets | 
        ForEach-Object {
            $CurrentIp = $_.IpAddress
            $CurrentPort = $_.Port            
            Get-CertInfo -IPAddress $CurrentIp -Port $CurrentPort -ErrorAction SilentlyContinue  
        } 
        #>

        $MyScriptBlock = {            
            $CurrentIp = $_.IpAddress
            $CurrentPort = $_.Port            
            Get-CertInfo -IPAddress $CurrentIp -Port $CurrentPort -ErrorAction SilentlyContinue  
        }

        $DraftResults = $targets | Invoke-Parallel -ScriptBlock $MyScriptBlock -ImportSessionFunctions -ImportVariables -Throttle $Threads -RunspaceTimeout 2 -ErrorAction SilentlyContinue
        
        # ------------------------------
        # Get unique list of domains
        # ------------------------------
        $AltDomainList = $DraftResults | where SubjectAltName -notlike "" | Select-Object SubjectAltName -ExpandProperty SubjectAltName                   
        $OrgDomainList = $DraftResults | where SubjectDomain -notlike "" | Select-Object SubjectDomain -ExpandProperty SubjectDomain      
        $DomainList = $AltDomainList+$DomainList | Select-Object @{Name="DomainName";Expression={$_}} | Sort-Object DomainName -Unique             
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


# -------------------------------------------
# Function:  Get-CertInfo
# -------------------------------------------
# Author: Scott Sutherland (@_nullbind), NetSPI 
# Based on work by Rob VandenBrink.
# References: https://isc.sans.edu/forums/diary/Assessing+Remote+Certificates+with+Powershell/20645/ 
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


# -------------------------------------------
# Function:  Invoke-Arin-Lookup
# -------------------------------------------
# Author: Scott Sutherland (@_nullbind), NetSPI 
function Invoke-Arin-Lookup
{ 
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
