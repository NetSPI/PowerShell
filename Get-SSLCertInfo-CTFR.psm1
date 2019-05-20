function Get-SSLCertInfo-CTFR
{
    <#                 
        Script: Get-SSLCertInfo-CTFR

        Version: 2.3

        Description
        This script can be used to download domain name information
        found in registered SSL certificates from the crt.sh API.         
        It supports:
        - Providing a domain target
        - Providing a domain target list from a file
        - Providing a domain target from the pipeline
        - Resolving IPs for identified domains
        - Attempting to identify Active Directory domains from results 
        - Exporting to nmap format
        - It returns a data table format that can be used to export and sort as well        
        
        Author Information
        - Based on https://github.com/UnaPibaGeek/ctfr
        - Ported by Karl Fosaaen
        - Modified by Scott Sutherland        

        Example Commands

        # Standard output with domain provided 
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com

        # Standard output with domain provided in list
        Get-SSLCertInfo-CTFR -Verbose -domainList c:\temp\domains.txt

        # Standard with domain provided in pipeline
        "netspi.com" | Get-SSLCertInfo-CTFR -Verbose

        # Standard output and list potential active directory domains
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -ShowAdDomains 

        # Standard output and list potential active directory domains and save them to a file (while doing al the other things)
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -ShowAdDomains -ADOutputFile c:\temp\new.txt

        # Standard output and resolve IP addresses
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -resolveDNS      
        
        # Standard output, resolve IP addresses, and perform arin lookup
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -resolveDNS -ArinLookup            
        
        # Standard output and resolve IP addresses, also output to an nmap file
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -resolveDNS -NmapOutput results.xml
        Get-SSLCertInfo-CTFR -Verbose -domain domain.com -resolveDNS -NmapOutput results
               
        # Examples showing how to capture the output and write it out to differant file types
        $Results = Get-SSLCertInfo-CTFR -Verbose -domain domain.com
        $Results
        $Results | Export-Csv ctrdomains.csv -notypeinformation
        $Results | Export-Clixml ctrdomains.xml 

        Example Output

        PS C:\> $Results = Get-SSLCertInfo-CTFR -Verbose -ShowAdDomains  -domain "other.com" -domainList C:\temp\domains.txt 
        VERBOSE: Imported 2 domain/keyword targets from the provided file.
        VERBOSE: Imported 1 domain/keyword targets from command line.
        VERBOSE: Targeting 2 unique domains/keywords.
        VERBOSE: netspi.com
        VERBOSE:  - Pulling records from crt.sh
        VERBOSE:  - Cleaning data
        VERBOSE:  - Processing sub domains
        VERBOSE: other.com
        VERBOSE:  - Pulling records from crt.sh
        VERBOSE:  - Cleaning data
        VERBOSE:  - Processing sub domains
        VERBOSE: Checking for potential Active Directory domains.
        VERBOSE: 2 potential Active Directory domains were found.
        VERBOSE: - win.other.com
        VERBOSE: - email.other.com
        VERBOSE: 228 domains found.
        VERBOSE: All done.

        PS C:\> $Results

        Domain     SubDomain                         IP
        ------     ---------                         --
        netspi.com *.netspi.com                        
        netspi.com autodiscover.netspi.com             
        netspi.com av.netspi.com                       
        netspi.com blog.netspi.com                     
        netspi.com blogs.netspi.com   
        
        Todo
        Other things to pull from the certs
        - company name
        - location
        - verify alt names
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        HelpMessage="The domain to lookup.")]
        [string]$domain,
        [Parameter(Mandatory=$false,
        HelpMessage="The file to output in nmap xml.")]
        [string]$nmapOutput,
        [Parameter(Mandatory=$false,
        HelpMessage="Path to file containing list of domain names or company names. One per line.")]
        [string]$domainList,
        [Parameter(Mandatory=$false,
        HelpMessage="Do DNS lookups for each returned host.")]
        [switch]$resolveDNS,
        [Parameter(Mandatory=$false,
        HelpMessage="List potential Active Directory domains.")]
        [switch]$ShowAdDomains,    
        [Parameter(Mandatory=$false,
        HelpMessage="File to save list of potential Active Directory domains to.")]
        [string]$ADOutputFile,
        [Parameter(Mandatory=$false,
        HelpMessage="Look up ip address owner.")]
        [switch]$ArinLookup
    )

    Begin
    {
        # Ignore certs for this host, since PowerShell is taking issue with it
        try{
            add-type "
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            }
            "
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        }catch{
        
        }

        # For return a list of Resolved IPs
        $DomainsFound = New-Object System.Data.DataTable
        $DomainsFound.Columns.Add("Domain") | Out-Null
        $DomainsFound.Columns.Add("CertDomain") | Out-Null
        $DomainsFound.Columns.Add("IpAddress") | Out-Null
        $DomainsFound.Columns.Add("IpOwner") | Out-Null
        $DomainsFound.Columns.Add("IpStartRange") | Out-Null
        $DomainsFound.Columns.Add("IpEndRange") | Out-Null
        $DomainsFound.Columns.Add("IpCountry") | Out-Null
        $DomainsFound.Columns.Add("IpCity") | Out-Null
        $DomainsFound.Columns.Add("IpZip") | Out-Null
        $DomainsFound.Columns.Add("IpISP") | Out-Null
        $DomainsFound.Columns.Add("CertEffectiveDate") | Out-Null
        $DomainsFound.Columns.Add("CertExpirationDate") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerCountry") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerState") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerCity") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerOrg") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerOU") | Out-Null
        $DomainsFound.Columns.Add("CertIssuerCN") | Out-Null   

        # Get domains or company list from a file
        if($domainList){
            
            if((Test-Path $domainList)){
                
                $ProvidedDomains = gc $domainList
                $DomainCount = $ProvidedDomains.count
                Write-Verbose "Imported $DomainCount domain/keyword targets from the provided file." 
            }else{
                Write-Verbose "Couldn't find $domainList, aborting."
                break  
            }
        }

        # Append domains to list of 
        if($domain){
            $ProvidedDomains += "$domain"
            Write-Verbose "Imported 1 domain/keyword targets from command line."
        }              
    }

    Process
    {
        # Append pipline domains to list of 
        if($_){
            $ProvidedDomains += "$_"
            Write-Verbose "Imported 1 domain targets from pipeline."
        } 

        # Check for list of targets
        if(-not $ProvidedDomains){
            Write-Verbose "No targets have been provided, aborting."
            #break
        }else{
            $ProvidedDomains = $ProvidedDomains |Select -Unique
            $DomainCount = $ProvidedDomains.count
            Write-Verbose "Targeting $DomainCount unique domains/keywords."            
        } 

        # Run through each of the domains in the list
        $ProvidedDomains | 
        ForEach-Object {
            
            $CurrentTarget = $_

            # URL to get the JSON response from
            $url = "https://crt.sh/?q=%.$CurrentTarget&output=json"

            # ---------------------
            # Grab data from crt.sh
            # ---------------------
            try
            {
                # Make the request to crt.sh      
                Write-Verbose "$CurrentTarget"  
                Write-Verbose " - Pulling records from crt.sh"          
                $JSON = Invoke-RestMethod -Uri $url -Verbose:$false
        
                # Parse initial results
                Write-Verbose " - Cleaning data"
                $DomainsUnique = $JSON | Sort-Object name_value -Unique       
            }
            catch
            {
                Write-Host "The Request out to crt.sh failed."
                break
            }  

            Write-Verbose " - Processing sub domains"
             
            # ---------------------
            # Process records      
            # ---------------------                
            $DomainsUnique | 
            ForEach-Object {

                # Parse record
                $SubDomain = $_.name_value 
                $EffectiveDate = $_.not_before
                $ExpirationDate = $_.not_after               
                $SubjectArray = $_.issuer_name -split(",")
                $SubjectArray | 
                ForEach-Object{
        
                    $item = $_.ToString().Trim()
                    $itemParts = $item -split("=")
        
                    # Set country
                    if($itemParts[0] -like "C"){        
                        $IssuerCountry = $itemParts[1] 
                    }

                    # Set state
                    if(($itemParts[0] -like "S") -or ($itemParts[0] -like "ST")){        
                        $IssuerState = $itemParts[1] 
                    }

                    # Set city
                    if($itemParts[0] -like "L"){        
                        $IssuerCity = $itemParts[1]
                    }

                    # Set Oranization
                    if($itemParts[0] -like "O"){        
                        $IssuerOrg = $itemParts[1] -replace ("`"","")
                    }

                    # Set Oranization Unit
                    if($itemParts[0] -like "OU"){           
                        $IssuerOU = $itemParts[1]             
                    }

                    # Set Domain
                    if($itemParts[0] -like "CN"){        
                        $IssuerCN = $itemParts[1] 
                    }
                }
                
                # set resolveDNS if $arinlookup
                if($ArinLookup){
                    $resolveDNS = $true
                }

                # Check if user asked for resolution
                if($resolveDNS){ 

                    # Match Wildcard domains            
                    if ($_ -match '\*'){   
                
                        # Add record                
                        $DomainsFound.Rows.Add($CurrentTarget, 
                        $SubDomain,
                        'N/A',
                        '',
                        '',
                        '',
                        '',
                        '',
                        '',
                        '',
                        $EffectiveDate,
                        $ExpirationDate,
                        $IssuerCountry,
                        $IssuerState,
                        $IssuerCity,
                        $IssuerOrg,
                        $IssuerOU,
                        $IssuerCN ) | Out-Null                                                                                        
                    }else{

                        Write-Verbose " - Resolving $CurrentTarget - $subdomain"
                 
                        # Attempt to resolve IP for domain
                        $dnsIP = Resolve-DnsName $SubDomain -ErrorAction SilentlyContinue -Verbose:$false  | 
                        Select -ExpandProperty IPAddress -First 1 -ErrorAction SilentlyContinue

                        # Add IP if one is resolved
                        if ($dnsIP){
                            $DomainsFound.Rows.Add($CurrentTarget, 
                            $SubDomain,
                            $dnsIP,
                            '',
                            '',
                            '',
                            '',
                            '',
                            '',
                            '',
                            $EffectiveDate,
                            $ExpirationDate,
                            $IssuerCountry,
                            $IssuerState,
                            $IssuerCity,
                            $IssuerOrg,
                            $IssuerOU,
                            $IssuerCN) | Out-Null                                                         
                        }else{

                            # try the A record
                            $dnsIP = Resolve-DnsName $SubDomain -ErrorAction SilentlyContinue -Verbose:$false -Type A | 
                            Select -ExpandProperty IP4Address -Unique -ErrorAction SilentlyContinue

                            # Add something either way
                            if ($dnsIP -is [array]){
                                $DomainsFound.Rows.Add($CurrentTarget, 
                                $SubDomain,
                                $dnsIP[0],
                                '',
                                '',
                                '',
                                '',
                                '',
                                '',
                                '',
                                $EffectiveDate,
                                $ExpirationDate,
                                $IssuerCountry,
                                $IssuerState,
                                $IssuerCity,
                                $IssuerOrg,
                                $IssuerOU,
                                $IssuerCN) | Out-Null 
                            }else{
                                $DomainsFound.Rows.Add($CurrentTarget, 
                                $SubDomain,
                                $dnsIP,
                                '',
                                '',
                                '',
                                '',
                                '',
                                '',
                                '',
                                $EffectiveDate,
                                $ExpirationDate,
                                $IssuerCountry,
                                $IssuerState,
                                $IssuerCity,
                                $IssuerOrg,
                                $IssuerOU,
                                $IssuerCN) | Out-Null 
                            }
                        }  
                    
                    }                                                                                                                                                           
                }else{ # end resolve dns if
                                
                            $DomainsFound.Rows.Add($CurrentTarget, 
                            $SubDomain,
                            '',
                            '',
                            '',
                            '',
                            '',
                            '',
                            '',
                            '',
                            $EffectiveDate,
                            $ExpirationDate,
                            $IssuerCountry,
                            $IssuerState,
                            $IssuerCity,
                            $IssuerOrg,
                            $IssuerOU,
                            $IssuerCN) | Out-Null 
                }                 
            }                         
        }

        # ---------------------
        # Resolve arin if asked
        # ---------------------          
        if($resolveDNS -and $ArinLookup){
            Write-Verbose "Processing arin lookups:"
            $DomainsFoundArin = $DomainsFound | 
            foreach {
                $rdomain = $_.domain
                $rsubdomain = $_.certdomain
                $rip = $_.ipaddress
                Write-Verbose "  - Processing arin lookups - $rsubdomain ($rip)"                
                Invoke-Arin-Lookup -Verbose -IpAddress $rip -Domain $rdomain -SubDomain $rsubdomain -CertEffectiveDate $EffectiveDate -CertExpirationDate $ExpirationDate -CertIssuerCountry $IssuerCountry -CertIssuerState $IssuerState -CertIssuerCity $IssuerCity  -CertIssuerOrg $IssuerOrg -CertIssuerOU $IssuerOU -CertIssuerCN $IssuerCN -ErrorAction SilentlyContinue
            }
        }

        $DomainsFoundArin

        # ---------------------
        # Output file if asked 
        # Note: nmap format for easy importing
        # ---------------------
        if ($NmapOutput){     
        
                if($DomainsFoundArin){
                    $targetlist = $DomainsFoundArin
                }else{   
                    $targetlist = $DomainsFound
                }    

                # Not utilizing actual XML functions here, because building NMap style strings was easier...
                $doc = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" args="none" start="" startstr="" version="" xmloutputversion="1.04">'

                foreach ($entry in $targetlist){
                    if ($_ -match '\*'){
                
                    #Don't include the * domains
                    }else{
                
                        $strBuilder = '<host><address addr="'+$entry.IP+'" addrtype="ipv4"/><hostnames><hostname name="'+$entry.SubDomain+'" type="PTR"/></hostnames><ports><extraports state="closed" count="999"><extrareasons reason="resets" count="999"/></extraports><port protocol="tcp" portid="-2"><state state="open" reason="syn-ack" reason_ttl="62"/><service name="none" method="table" conf="3"/></port></ports></host>'
                        $doc += $strBuilder
                    }
                }
            
                # Close out the nmaprun section    
                $doc += '</nmaprun>'

                # Write File            
                if ($NmapOutput -match '.xml'){
                    write-verbose "Creating output file $NmapOutput.xml"
                    $doc | Out-File $NmapOutput
                }else{
                    $outfileName = $NmapOutput+'.xml'
                    write-verbose "Creating output file $outfileName"; 
                    $doc | Out-File $outfileName
                }
                
            }            
    }

    End
    {
        # Check for potential ad domains
        if($ShowAdDomains){
            
            # All domains with > 2 ".", filter out www, drop host name, uniuque display
            Write-Verbose "Checking for potential Active Directory domains."
            $PotentialAdDomains = New-Object System.Data.DataTable 
            $PotentialAdDomains.Columns.add("domain") | Out-Null                
            $DomainsFound | 
            ForEach-Object {
                #$CheckDomain = "hostname.subdomain.domain.com"
                $CheckDomain = $_.CertDomain
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
        
        # Display results with IP resolution
        if($DomainsFoundArin){
            $targetlist = $DomainsFoundArin
        }else{
            $targetlist = $DomainsFound
        }

        $FinalDomainCount = $targetlist.rows.Count
        Write-Verbose "$FinalDomainCount domains found."
        $targetlist           
        
        # Status user.  
        Write-Verbose "All done."         
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
        HelpMessage="Original domain.")]
        [string]$Domain,
        [Parameter(Mandatory=$false,
        HelpMessage="Sub domain.")]
        [string]$SubDomain,
        [Parameter(Mandatory=$false,
        HelpMessage="CertEffectiveDate.")]
        [string]$CertEffectiveDate,
        [Parameter(Mandatory=$false,
        HelpMessage="CertExpirationDate.")]
        [string]$CertExpirationDate,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerCountry.")]
        [string]$CertIssuerCountry,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerState.")]
        [string]$CertIssuerState,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerCity.")]
        [string]$CertIssuerCity,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerOrg.")]
        [string]$CertIssuerOrg,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerOU.")]
        [string]$CertIssuerOU,
        [Parameter(Mandatory=$false,
        HelpMessage="CertIssuerCN.")]
        [string]$CertIssuerCN
    )

    Begin
    {      
        # IP info table
        $TblIPInfo = new-object System.Data.DataTable
        $TblIPInfo.Columns.Add("Domain") | Out-Null
        $TblIPInfo.Columns.Add("Certdomain") | Out-Null
        $TblIPInfo.Columns.Add("IpAddress") | Out-Null
        $TblIPInfo.Columns.Add("IpOwner") | Out-Null
        $TblIPInfo.Columns.Add("IpStartRange") | Out-Null
        $TblIPInfo.Columns.Add("IpEndRange") | Out-Null
        $TblIPInfo.Columns.Add("IpCountry") | Out-Null
        $TblIPInfo.Columns.Add("IpCity") | Out-Null
        $TblIPInfo.Columns.Add("IpZip") | Out-Null
        $TblIPInfo.Columns.Add("IpISP") | Out-Null 
        $TblIPInfo.Columns.Add("CertEffectiveDate") | Out-Null
        $TblIPInfo.Columns.Add("CertExpirationDate") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerCountry") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerState") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerCity") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerOrg") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerOU") | Out-Null
        $TblIPInfo.Columns.Add("CertIssuerCN") | Out-Null 

        # Lookup source IP owner 
        if($IpAddress -notlike ""){

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
            $IpCity = $results2.query.city.'#cdata-section'
            $IpZip = $results2.query.zip.'#cdata-section'
            $IpISP = $results2.query.isp.'#cdata-section'

            # Put results in the data table   
            $TblIPInfo.Rows.Add(
              "$Domain",
              "$SubDomain",
              "$IpAddress",
              "$IpOwner",
              "$IpStart",
              "$IpEnd",
              "$IpCountry",
              "$IpCity",
              "$IpZip",
              "$IpISP",
              $EffectiveDate,
              $ExpirationDate,
              $IssuerCountry,
              $IssuerState,
              $IssuerCity,
              $IssuerOrg,
              $IssuerOU,
              $IssuerCN) | Out-Null           
        }else{
            # Put results in the data table   
            $TblIPInfo.Rows.Add(
              "$Domain",
              "$SubDomain",
              "$IpAddress",
              "$IpOwner",
              "$IpStart",
              "$IpEnd",
              "$IpCountry",
              "$IpCity",
              "$IpZip",
              "$IpISP",
              $EffectiveDate,
              $ExpirationDate,
              $IssuerCountry,
              $IssuerState,
              $IssuerCity,
              $IssuerOrg,
              $IssuerOU,
              $IssuerCN) | Out-Null   
        }

        # Display results
        $TblIPInfo                   
    }

    End
    {
    }
}
