function Resolve-DnsDomainValidationToken
{
    <#
            .SYNOPSIS
            This function can be used to query for DNS TXT records that 
            may be domain valiation tokens that can be used to fingerprint 
            service providers being used by the target company.
            .PARAMETER $Domain
            Single domain to process.
            .PARAMETER $DomainList
            List of domains to be processes.
            .PARAMETER $UrlList
            List of URLs to be processes.
            .PARAMETER $OutfileToken
            The output file path for fingerprinted tokens.
            .PARAMETER $OutfileTxt
            The output file path for txt records.
            .EXAMPLE
            PS C:\> Resolve-DnsDomainValidationToken -$DomainList c:\temp\domains.txt -$UrlList c:\temp\urls.txt -Outfile c:\temp\DomainValidationTokenInformation.csv
	        .NOTES
	        Author: Scott Sutherland (@_nullbind)
            Version: 1.0
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'Single domain to be processes.')]
        [string]$Domain,
        [Parameter(Mandatory = $false,
        HelpMessage = 'List of domains to be processes.')]
        [string]$DomainList,
        [Parameter(Mandatory = $false,
        HelpMessage = 'List of URLs to be processes.')]
        [string]$UrlList,
        [Parameter(Mandatory = $false,
        HelpMessage = 'The output file path for known domain valition tokens.')]
        [string]$OutfileToken = ".\Dns_Txt_Records_Domain_Validation_Tokens.csv",
        [Parameter(Mandatory = $false,
        HelpMessage = 'The output file path for all dns txt records.')]
        [string]$OutfileTxt = ".\Dns_Txt_Records.csv"
    )

    # Check for imports
    if(-not $DomainList -and -not $UrlList -and -not $Domain){
        Write-Output "[-] Please provide a list of domains or URLs."
        Break
    }

    # Test access to domain list
    if($DomainList){
        if(Test-Path $DomainList)
        {
            # Import list of domains from files                      
            Write-Verbose "[+] Loading domains from $DomainList"
            $DomainsFromFile = gc $DomainList
        }else{
            write-Output "[-] $DomainList is not accessible, aborting."
            break
        }
    } 

    # Test access to domain list
    if($UrlList){
        if(Test-Path $UrlList)
        {
            # Import list of URLs            
            Write-Verbose "[+] Loading URLs $UrlList"
            $URLs = gc $UrlList

            # Parse URLs into domains
            Write-Verbose "[+] Parsing domains from URLs"
            $DomainsFromUrls = $URLs|
            ForEach-Object{
    
                # Parse domain 
                # https://stackoverflow.com/questions/14363214/get-domain-from-url-in-powershell
	            # Parse domain.com from "http://www.domain.com/folder/" 
                try{
                    $_.substring((($_.substring(0,$_.lastindexof("."))).lastindexof(".")+1),$_.length-(($_.substring(0,$_.lastindexof("."))).lastindexof(".")+1))
                }catch{
                }
            } 
        }else{
            write-Output "[-] $UrlList is not accessible, aborting."
            break
        }
    }

    # Combine domain lists    
    $FinalDomainList = $DomainsFromFile + $DomainsFromUrls + $domain
    $DomainCount = $FinalDomainList.Count
    $DomainCounter = 0

    # Check that list has more than 0 domains
    if($DomainCount -eq 0){
        write-Output "[-] No domains provided, aborting."
    }

    # Get TXT records for domains
    Write-Verbose "[+] Creating final list of unique target domains"
    $txtlist = $FinalDomainList | select -Unique |
    ForEach-Object{
        try{
            $DomainCounter = $DomainCounter + 1
            $CurrentPercent = ($DomainCounter/$DomainCount).tostring("P")
            Write-Verbose "[+]   $DomainCounter of $DomainCount ($CurrentPercent) Grabbing TXT for $_"
            Resolve-DnsName -Type TXT $_ -Verbose:$false -ErrorAction SilentlyContinue | where type -like 'TXT'
        }catch{
        }
    }  
    
    # Filter output and write to csv file
    $TxtRecordList = $txtlist  | where type -like txt |  select name,type,strings | 
    ForEach-Object {
        $myname = $_.name
        $_.strings | 
        foreach {
        
            $object = New-Object psobject
            $object | add-member noteproperty domain $myname
            $object | add-member noteproperty txtstring $_

            if(($_ -notlike "v=spf*") -and ($_ -notlike "*ip4*"))
            {   
                $object
            }
        }
    } | Sort-Object name

    # Save results to CSV    
    if($TxtRecordList){
        Write-Verbose "[+] Saving TXT records to $OutfileTxt"
        $TxtRecordList | Export-Csv -NoTypeInformation $OutfileTxt
    }else{
        Write-Verbose "[-] No domains were found with TXT records."
        break
    }

    # Create data table containins known dns txt domain valiation tokens
    $DomainTokenList = New-Object System.Data.DataTable
    $null = $DomainTokenList.Columns.Add("Category")
    $null = $DomainTokenList.Columns.Add("Confidence")
    $null = $DomainTokenList.Columns.Add("Count")
    $null = $DomainTokenList.Columns.Add("Description")
    $null = $DomainTokenList.Columns.Add("DomainValidationToken")
    $null = $DomainTokenList.Columns.Add("Example")
    $null = $DomainTokenList.Columns.Add("Name")
    $null = $DomainTokenList.Columns.Add("SiteReference")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","Unknown","Zoom Meeting Software","Zoom","ZOOM_verify_EPq123456789_1234-1234","zoom.com","https://www.google.com")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","149785","G Suite","google-site-verification","google-site-verification=ZZYRwyiI6QKg0jVwmdIha68vuiZlNtfAJ90msPo1i7E","gmail.com","https://support.google.com/a/answer/2716802?hl=en")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","70797","Microsoft Office 365","MS=","MS=ms38205980 or MS=AAD33B75124A131B85F0845428DA3BFF9DAC703","Microsoft Office 365","https://docs.microsoft.com/en-us/office365/admin/setup/add-domain?view=o365-worldwide")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","16028","facebook domainverification","facebook-domain-verification","facebook-domain-verification=zyzferd0kpm04en8wn4jnu4ooen5ct","facebook.com","https://developers.facebook.com/docs/sharing/domain-verification/")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","90","11486","CA ssl cert ","_globalsign-domain-verification","_globalsign-domain-verification=Zv6aPQO0CFgBxwOk23uUOkmdLjhc9qmcz-UnQcgXkA","globalsign.com","https://support.globalsign.com/customer/en/portal/articles/2167245-performing-domain-verification---dns-txt-record")
    $null = $DomainTokenList.Rows.Add("Electronic Signing,Cloud Services","90","5097","Adobe domain validation","adobe-idp-site-verification","adobe-idp-site-verification=ffe3ccbe-f64a-44c5-80d7-b010605a3bc4 ","Adobe Enterprise Services","https://helpx.adobe.com/enterprise/using/verify-domain-ownership.html")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","4093","Amazon Simple Email","amazonses","amazonses:ZW5WU+BVqrNaP9NU2+qhUvKLdAYOkxWRuTJDksWHJi4=","Amazon Simple Email","https://docs.aws.amazon.com/ses/latest/DeveloperGuide/dns-txt-records.html")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","90","3605","CA ssl cert ","globalsign-domain-verification","globalsign-domain-verification=zPlXAjrsmovNlSOCXQ7Wn0HgmO--GxX7laTgCizBTW","globalsign.com","https://support.globalsign.com/customer/en/portal/articles/2167245-performing-domain-verification---dns-txt-record")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","3486","Collaboration software jira confluence","atlassian-domain-verification","atlassian-domain-verification=Z8oUd5brL6/RGUMCkxs4U0P/RyhpiNJEIVx9HXJLr3uqEQ1eDmTnj1eq1ObCgY1i","atlassian services","https://confluence.atlassian.com/cloud/verify-a-domain-for-your-organization-873871234.html")
    $null = $DomainTokenList.Rows.Add("Cloud Services","50","2700","mailru-","mailru-","mailru-verification: fa868a61bb236ae5 ","mailru-","mailru-")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","2698","Russian search engine. Verify site ownership. Site metrics.","yandex-verification","yandex-verification=fb9a7e8303137b4c","yandex.com","https://www.webnots.com/yandex-webmaster-tools/")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","2429","Salesforce's Marketing Automation Solution. The Token appears to consist of a client id and a hash value.","pardot","pardot_104652_*=b9b92faaea08bdf6d7d89da132ba50aaff6a4b055647ce7fdccaf95833d12c17","https://www.salesforce.com/form/sem/pardot/","https://help.salesforce.com/articleView?id=000313465&language=en_US&type=1&mode=1")
    $null = $DomainTokenList.Rows.Add("Electronic Signing","90","2098","Electronic document signing.","docusign","docusign=ff4d259b-5b2b-4dc7-84e5-34dc2c13e83e","docusign.com","https://support.docusign.com/en/guides/org-admin-guide-domains")
    $null = $DomainTokenList.Rows.Add("Collaboration","80","1468","Collaboration and screensharing.","webexdomainverification","webexdomainverification.P7KF=bf9d7a4f-41e4-4fa3-9ccb-d26f307e6be4","webex","https://help.webex.com/en-us/nxz79m5/Add-Verify-and-Claim-Domains")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","1358","Sales and market email toolbox.","Sendinblue-code","Sendinblue-code:faab5d512036749b0f69d906db2a7824 ","www.sendinblue.com","https://help.sendinblue.com/hc/en-us/articles/115000240344-Step-1-Delegating-your-subdomain")
    $null = $DomainTokenList.Rows.Add("Email","100","1005","online mail","zoho-verification","zoho-verification=zb[sequentialnumber].zmverify.zoho.[com|in]","zoho.com","https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&uact=8&ved=2ahUKEwjx97mIlfHiAhVL2qwKHS3bDPYQFjAAegQIARAB&url=https%3A%2F%2Fwww.zoho.com%2Fmail%2Fhelp%2Fadminconsole%2Fdomain-verification.html&usg=AOvVaw0xHje1E_BK70kkZccDOzeb")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","690","file sharing online","dropbox-domain-verification","dropbox-domain-verification=zsp1beovavgv","dropbox.com","https://help.dropbox.com/teams-admins/admin/domain-verification-invite-enforcement")
    $null = $DomainTokenList.Rows.Add("Collaboration","80","675","cisco webex meeting and remote desktop","ciscocidomainverification","ciscocidomainverification=f1d51662d07e32cdf508fe2103f9060ac5ba2f9efeaa79274003d12d0a9a745 ","webex.com","https://help.webex.com/en-us/nxz79m5/Add-Verify-and-Claim-Domains")
    $null = $DomainTokenList.Rows.Add("Security","50","607","","workplace-domain-verification","workplace-domain-verification=BEJd6oynFk3ED6u0W4uAGMguAVnPKY ","Spiceworks.com","https://community.spiceworks.com/topic/2151848-need-to-verify-a-domain-by-dns-text-record-hosted-by-europe-registry?source=recommended")
    $null = $DomainTokenList.Rows.Add("Security","90","590","search for email account in breaches","have-i-been-pwned-verification","have-i-been-pwned-verification=faf85761f15dc53feff4e2f71ca32510","haveibeenpwned.com","https://haveibeenpwned.com/DomainSearch")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","577","Citrix?","citrix-verification-code","citrix-verification-code=ed1a7948-6f0d-4830-9014-d22f188c3bab","citrix.com","Citrix")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","441","private secure internet browsing web browser","brave-ledger-verification","brave-ledger-verification=fb42f0147b2264aa781f664eef7d51a1be9196011a205a2ce100dc76ab9de39f","brave.com","https://support.brave.com/hc/en-us/articles/360021408352-How-do-I-verify-my-channel-")
    $null = $DomainTokenList.Rows.Add("Electronic Signing","90","427","Adobe Sign - https://acrobat.adobe.com/us/en/sign.html; similar to docusign; sign documents; maybe just adobe document cloud","adobe-sign-verification","adobe-sign-verification=fe9cdca76cd809222e1acae2866ae896 ","Adobe Sign / Document Cloud","https://helpx.adobe.com/sign/help/domain_claiming.html")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","70","384","Firebase Web App; seems like the value is a description of some kind; mobile Development and Publishing platform","firebase","firebase=solar-virtue-511 ","https://firebase.google.com/","https://medium.com/@alansimpson/connect-your-domain-or-subdomain-to-firebase-hosting-365c721c395a")
    $null = $DomainTokenList.Rows.Add("","70","384","","mscid","mscid=veniWolTd6miqdmIAwHTER4ZDHPBmT0mDwordEu6ABR7Dy2SH8TjniQ7e2O+Bv5+svcY7vJ+ZdSYG9aCOu8GYQ== ","O365","https://thoughtsofanidlemind.com/2012/03/28/dmarc-spf/")
    $null = $DomainTokenList.Rows.Add("Security","90","381","Network and app load testing saas","loaderio","loaderio=fefa7eab8eb4a9235df87456251d8a48","https://loader.io/","https://support.loader.io/article/20-verifying-an-app")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","70","270","Now part of https://bookry.com/","wmail-verification","wmail-verification: e5131794bf280cbde0d5366fe0c086c1 ","wmail/wavebox","https://blog.wavebox.io/introducing-wavebox/")
    $null = $DomainTokenList.Rows.Add("Cloud Services","70","230","GoDaddy Web Services","DZC","DZC: root-domain-where-ssl-be-installed.com","GoDaddy Web Services","https://www.godaddy.com/community/SSL-And-Security/SSL-Domain-Verification-with-DNS/td-p/42604 https://www.liontreegroup.com/godaddy-tips/dzc-txt-record-settings-for-godaddy-ssl-addon-domain-sans/")
    $null = $DomainTokenList.Rows.Add("Remote Management","70","208","citrix zenmobile auto-discovery was added","citrix.mobile.ads.otp","citrix.mobile.ads.otp=uwyegxiq71vl4t43ndh0kerk","citrix.com","https://support.citrix.com/article/CTX217369")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","90","205","This is a CA","swisssign-check","swisssign-check=","swisssign.com","https://www.swisssign.com/news/detail~newsID=5d91caee-8fc7-4af9-b63b-eadae419ff29~.html")
    $null = $DomainTokenList.Rows.Add("Remote Management","90","204","remote desktop","logmein-verification-code","logmein-domain-confirmation","logmeininc.com","https://support.logmeininc.com/openvoice/help/set-up-domains-ov710101")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","198","Feedblitz","blitz","blitz=mu-00dca132-7319e8a1-720c2961-cd6aa586","Feedblitz","https://www.feedblitz.com/quick-tips-where-can-i-edit-my-dkim-and-spf-authentication/")
    $null = $DomainTokenList.Rows.Add("Email","90","192","","protonmail-verification","protonmail-verification=","protonmail.com","https://protonmail.com/support/knowledge-base/dns-records/")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","184","Postman manage api Development and Publishing and management.","postman-domain-verification","postman-domain-verification=3de5919722c9d9d8ea76b8cb259f2c7b9b4f3aa8e5dec3266009abd88ce45eb4f24235d","getpostman","https://learning.getpostman.com/docs/postman/api_documentation/adding_and_verifying_custom_domains/")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","155","marketing and analytics seo","botify-site-verification","botify-site-verification=TDtyNBeR2RxMQH9BzBJdkBwcstAV0Hym","botify.com","https://www.botify.com/blog/validate-website-ownership-botify-analytics-BA")
    $null = $DomainTokenList.Rows.Add("Security","80","149","Status page for cloud platforms. Monitor and alert on things.","status-page-domain-verification","status-page-domain-verification=zkqb037zzpjs ","statuspage.io","https://help.statuspage.io/help/domain-ownership")
    $null = $DomainTokenList.Rows.Add("Security","80","130","Website application testing. Like whitehat.","tinfoil-site-verification","tinfoil-site-verification: f5fc756f1205b16596a2cfcd9ab78ec91038ddf5=316e472fbc50c0572052df1cf8a1ed","tinfoilsecurity.com","https://www.tinfoilsecurity.com/badge_verify/a79e560c7ff85377825260bae8df40b49fb9246a")
    $null = $DomainTokenList.Rows.Add("Collaboration","80","128","cisco webex meeting and remote desktop","cisco-ci-domain-verification","cisco-ci-domain-verification=69b7ecaa850d9fd7936048693d274ee5a1baaaad20c17e9c47d27bddd0f40a9e","webex.com","https://help.webex.com/en-us/nxz79m5/Add-Verify-and-Claim-Domains")
    $null = $DomainTokenList.Rows.Add("Cloud Services","80","120","domain validation for godaddy web services and hosting","godaddyverification","godaddyverification=/FCP2SOvl1RnIeOnyBD6RA==","godaddy.com","https://www.godaddy.com/help/verify-domain-ownership-html-or-dns-for-my-ssl-certificate-7452")
    $null = $DomainTokenList.Rows.Add("Configuration Management","70","106","android mobile mdm","android-enroll","android-enroll=https://ldgateway.it.ohio-state.edu/rtc/cio-ldms10-prd/MDM/api/v1/enroll/AndroidEnroll ","android mobile mdm","https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Mobility/mobl-DNS.htm")
    $null = $DomainTokenList.Rows.Add("Configuration Management","70","106","android mobile mdm","android-mdm-enroll","android-mdm-enroll=https://smm.directv.com/MobileEnrollment/SYMC-AndroidEnroll.aspx ","android mobile mdm","https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Mobility/mobl-DNS.htm")
    $null = $DomainTokenList.Rows.Add("Security","90","106","google oauth authenticaiton setup","anodot-domain-verification","anodot-domain-verification=22a37350bc036e536d9fbb047513c15f1d09de30af60f87c20af295836a05e53","googlel oauth","https://support.anodot.com/hc/en-us/articles/360002933774-Google-OAuth-Authentication-")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","100","news agregator","dailymotion-domain-verification","dailymotion-domain-verification=dmvxv0c2t7odxi7pj","dailymotion.com","https://faq.dailymotion.com/hc/en-us/articles/115008958347-Verify-your-domains")
    $null = $DomainTokenList.Rows.Add("Collaboration","70","97","Collaboration","wrike-verification","wrike-verification=MjE4MTMxMTo0MzQ2NjY4ZjE3MTEyMDI4NTE4NDM2MWZjZTNkMmM0ZjgyZjlhOGNkNTQ3MjZkOTZjZWFh","wrike.com","https://www.wrike.com/")
    $null = $DomainTokenList.Rows.Add("Security","90","85","sophos center admin","sophos-domain-verification","sophos-domain-verification=2708d1d8924a1359cc43db0078cd07f54133bf6f ","sophos.com","https://docs.sophos.com/central/Customer/help/en-us/central/Customer/tasks/domainownershipgoogle.html")
    $null = $DomainTokenList.Rows.Add("Security","90","82","Secure awareness training, phishing","knowbe4-site-verification","knowbe4-site-verification=e04590e121eee5fbc18ada6449219119 ","knowbe4.com","https://support.knowbe4.com/hc/en-us/articles/360013430414-How-to-Add-and-Verify-Allowed-Domains")
    $null = $DomainTokenList.Rows.Add("Security","90","73","Application intelligence - network and application monitoring","Dynatrace-site-verification","Dynatrace-site-verification=57845654-842f-473b-9ecc-f9ea6588da30__gub9hiq590k5seias25p4l6h80","www.dynatrace.com","")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","70","Customer data collection and analytics.","segment-site-verification","segment-site-verification=zmq81eV2xBppwOnNid0CcwH0GR7d2OjK ","segment.com","segment.com")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","63","email marketing","mailigen-site-verification","mailigen-site-verification=","mailigen.com","https://support.mailigen.com/user-account-management/email-authentication")
    $null = $DomainTokenList.Rows.Add("Security","70","61","Early breach warning detection. Avoid account take over.  Take in list of humanint (ads integration), cross compare against breach data(dumps, botnets, osint). Notify if account is on the list.","spycloud-domain-verification","spycloud-domain-verification=0dd66cb4-3249-4fbc-8efd-e762bcbed4be ","spycloud.com","spycloud.com")
    $null = $DomainTokenList.Rows.Add("Configuration Management","90","57","Symantec MDM","OSIAGENTREGURL","OSIAGENTREGURL=","Symantec MDM","Symantec MDM")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","70","55","t-systems security from trust center - ssl / tls certs ca","_telesec-domain","_telesec-domain-validation=C39B6AD9CD4D02E721C87CBCD4D78EC6094063DF5FBA98703D34DC03C6C0AB67","t-systems","https://www.telesec.de/en/serverpass-en/support/domain-control/20-serverpass/640-verifiy-via-dns-entry")
    $null = $DomainTokenList.Rows.Add("Remote Management","90","55","web based remote desktop","teamviewer-sso-verification","teamviewer-sso-verification=e6d472220a1a4fa5805798babe01a9e4","teamviewer.com","https://community.teamviewer.com/t5/Knowledge-Base/Single-Sign-On-SSO/ta-p/30784")
    $null = $DomainTokenList.Rows.Add("Collaboration","80","52","line works  - secure collaboration","worksmobile-certification","worksmobile-certification=6baxzylmsujmwpgplx-p1cgtbmje8armo-lkv7vhih1","Line works","https://line.worksmobile.com/jp/en/")
    $null = $DomainTokenList.Rows.Add("Security","90","49","Crowd source penetration testing / Pentest broker.","bugcrowd-verification","bugcrowd-verification=ff8e6859d285e32323dd9f33396589f","bugcrowd.com","https://docs.bugcrowd.com/docs/okta")
    $null = $DomainTokenList.Rows.Add("Collaboration","80","47","cisco webex meeting and remote desktop","cisco-site-verification","cisco-site-verification=bef4f63a-650a-42f7-9b04-0fe42a4cc74a","webex.com","https://help.webex.com/en-us/nxz79m5/Add-Verify-and-Claim-Domains")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","80","46","lets encrypt","_acme-challenge.","","letsencrypt.org","https://letsencrypt.org/docs/challenge-types/")
    $null = $DomainTokenList.Rows.Add("Cloud Services","90","45","cloud platform and service","heroku-domain-verification","heroku-domain-verification=5bpsmgqd0irdsecvtkii8e9d0zwp33uszd4byfb6o","heroku.com","https://devcenter.heroku.com/articles/custom-domains")
    $null = $DomainTokenList.Rows.Add("Security","90","43","domain and application security vulnerability scanner  automated scanner","detectify-verification","detectify-verification=ecdfd75ed9ccaf3a5ea5d2e7787fe559","detectify.com","https://support.detectify.com/customer/en/portal/articles/2836806-verification-with-dns-txt-")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","40","cloudControl was a European company offering a platform as a service (PaaS) based in Berlin, Germany. Officially supported languages for development and deployment were Java, PHP, Python and Ruby via the open buildpack API originally developed by Heroku.  It appears to be shutdown.","cloudControl-verification","cloudControl-verification: 83079e515d44df99b106a5a0bd4e7a7ac62a0c95df3c8eca7cb53293405d0265","","https://github.com/cloudControl/documentation/blob/8a50b66a24a488d467d6986a3ab18b9ee80f9e01/Add-on-Documentation/Alias.md")
    $null = $DomainTokenList.Rows.Add("Unknown","0","38","All .cz domains","wwrr","wwrr 77.75.79.93 1 http 80 30 6 3","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","37","email marketing","mailjet-domain-validation","mailjet-domain-validation=LHHNkssYG","app.mailjet.com","https://app.mailjet.com/support/how-to-validate-an-entire-sending-domain,214.htm")
    $null = $DomainTokenList.Rows.Add("Unknown","0","37","Unknown","BPL","BPL=1251890","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Unknown","0","37","Unknown","d365mktkey","d365mktkey=1wlhlipgh0hrf2ajuh1wpo52u","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Security","90","34","cdn ddos protection fast delivery","aliyun-site-verification","aliyun-site-verification=e325af9c-cda4-4b57-abe0-78c294ee8c66","alibaba cdn","https://www.alibabacloud.com/help/doc-detail/86073.htm")
    $null = $DomainTokenList.Rows.Add("Unknown","0","33","Unknown","wl-verify","wl-verify=6dec2b5f8fcf3e099263","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Configuration Management","70","32","ios mobile mdm","iOS-enroll","iOS-enroll","ios mobile mdm","https://help.ivanti.com/ld/help/en_US/LDMS/10.0/Mobility/mobl-DNS.htm")
    $null = $DomainTokenList.Rows.Add("Security","90","30","","site24x7-domain-verification","site24x7-domain-verification=","support.site24x7.com","https://support.site24x7.com/portal/kb/articles/how-to-add-domain-verification-key-in-your-dns-txt-record")
    $null = $DomainTokenList.Rows.Add("Security","90","28","Akamai tool. The Cloudpiercer tool bundles several previously known methods with some stated new ones to simplify the reconnaissance against targets. It's a reconnaissance tool, not an attack tool. A potential attacker may use similar methods to search for a customer's datacenter IP addresses or netblock(s) but will have to use other services or technologies to perform an actual DDoS or web application attack. ","cloudpiercer-verification","cloudpiercer-verification=052ac7679a5268f05abb65c26bd9c42d","Akamai Cloud Peircer","https://cloudpiercer.org")
    $null = $DomainTokenList.Rows.Add("Financial Services","80","28","Inacct cloud accounting and financial management software.","intacct-esk","intacct-esk=4FED1A3F159E7D3FE053A006A8C05190","Inacct","https://online.sageintacct.com/Online-Google_ondemand_product_tour.html?gclid=EAIaIQobChMIjab5v9rT4wIVxcDACh2rbwjAEAAYASAAEgL3_vD_BwE")
    $null = $DomainTokenList.Rows.Add("Unknown","80","27","barracuda cloud control","bvm-site-verification","bvm-site-verification=353f1db0fefe6103683e27d8bd01cae925556bd1","Barracuda Campus","https://campus.barracuda.com/product/vulnerabilitymanager/doc/51191216/verifying-domains-without-email/")
    $null = $DomainTokenList.Rows.Add("Security","90","27","CDN  - ddos protections and faster content delivery","cloudflare-verify","cloudflare-verify","cloudflare.com","https://www.cloudflare.com/learning/dns/dns-records/dns-txt-record/")
    $null = $DomainTokenList.Rows.Add("Unknown","0","26","Unknown","SYSTEM","Unknown","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Unknown","0","25","Unknown","ACCOUNT","Unknown","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","24","Marketing and Analytics","drift-domain-verification","drift-domain-verification=1d71a8baf8b89a67c9731003d9f9c5da3335d1d57c3bd920a0f045408c0cd2ac ","drift.com","https://gethelp.drift.com/hc/en-us/articles/360019516813-Setting-Up-Email-Sending-Domains-DKIM-")
    $null = $DomainTokenList.Rows.Add("Unknown","0","24","Unknown","ReleaseWLIDNamespace","ReleaseWLIDNamespace=true","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Unknown","0","24","Unknown","Security code","Security code: 9ET-1B6-E1B","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","5","22","Appears to be a cloud based marketing service that doesn't exist anymore. ","LDLAUNCHPAD","LDLAUNCHPAD=https://infw0766.dmz2.schindler.com/launchpad.cloud","LaunchPad Cloud","https://twitter.com/launchpadcloud")
    $null = $DomainTokenList.Rows.Add("Collaboration","100","20","Allows zendesk products to send mail on behalf of the domain.  Products include live chat, messaging, call center, and smart self serve software.","zendeskverification","zendeskverification=e51d72884acd23d1  or zendeskverification.koovs.com=812c542af9bcd334","zendesk.com","https://support.zendesk.com/hc/en-us/articles/203683886-Allowing-Zendesk-to-send-email-on-behalf-of-your-email-domain")
    $null = $DomainTokenList.Rows.Add("Unknown","10","20","mimecast?","__mc[domprov]","__mc[domprov]:184013a53d7341dd9ec50972fca6e3d3","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Collaboration","50","20","Online form","digitalpoint-site-verify","digitalpoint-site-verify:01cf82cd6e91f4100953215b09014e00","https://forums.digitalpoint.com/","https://www.dynadot.com/community/forums/f7-domain-name-help/need-help-setting-up-dns-txt-record-for-dp-verification-link-5429.html")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","18","Software Delivery Management","cloudbees-domain-verification","cloudbees-domain-verification:2f32323b91e85853bc049662a11ce6c136f769f1","cloudbees.com","https://support.cloudbees.com/hc/en-us/articles/360017607331-How-to-set-up-SSO-with-SAML-based-IdP-to-access-CloudBees-services-")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","17","rolling phone screens tablet ipad","beam-verification","beam-verification=0Lnhcd30mv6Z9ihMtU7T71MtNzFCrOfMcRlmXES7wQt9vCfQ","beam (suitabletech.com)","https://suitabletech.com/support/helpcenter/enterprise-admin-full-listing/2405-sso-domain-verification")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","50","17","Certificate Authority","_netlock","_netlock=U2FsdGVkX1%2B7A5kTAuAMWcxfl%2FMbKick08cuVOeOKxbYSmZVGmj30lndGGv1Sq%2B1%0AWhdhzhXNseq1eMn1C5jGIoQodlXkoH5XY9qKas%2Fd4K%2Fc4GfJbb5S8x04%2BVsOMvJw%0A","https://www.netlock.hu/USEREN/html/cacrl.html","Unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","16","Russian based web analytics company.","openstat-verification","openstat-verification= 158f75fa5fcb96fdc151b1be0be15d669dd35d66","OpenStat","https://www.similartech.com/technologies/openstat")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","90","15","CA","QuoVadis","QuoVadis=6f4acc85-2f23-4cd4-b723-77f106b3ed65","quovadisglobal.com","https://support.quovadisglobal.com/kb/a489/ssl-domain-validation-using-dns-change.aspx")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","14","Spanish based email marketing.","Acumbamail-domain-verification","Acumbamail-domain-verification= 0252062c-1279-11e7-9553-0050569a455d","Acumbamail","https://acumbamail.com/soporte/campanas/anadir-y-verificar-un-dominio-completo/")
    $null = $DomainTokenList.Rows.Add("Unknown","0","14","Unknown","blog","Unknown","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Security","90","13","numbo is an anti-spam cloud service","inumbo-verification","inumbo-verification=0acf6d592b1ea31a195d837679ba48175c2e8daf","https://control.inumbo.com/api","https://control.inumbo.com/api")
    $null = $DomainTokenList.Rows.Add("Cloud Services","80","13","The are commonly used by Microsoft.  They appear to be issues sequentially.  Largely associated with domains out of Portugal based on sample.","mtc","mtc=ms98218371","Microsoft Azure DNS","https://social.msdn.microsoft.com/Forums/en-US/15525664-5364-4d87-b76a-ad9a42c31d1f/how-to-create-a-ms-or-txt-record-in-microsoft-dns?forum=WindowsAzureAD")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","13","Marketing and sales platform for brands & influencers.","perlu-site-verification","perlu-site-verification=c031ba2f8ba2a8f3a2da5d84daa227e896777394c50e77d680095f5ddb00dfd0","Perlu","https://www.perlu.com/")
    $null = $DomainTokenList.Rows.Add("unknown","0","13","These appear to be associated with Russian websites.","ulogin-verification","ulogin-verification:3bc2712defb6","unknown","https://help.ea.com/en-us/help/account/origin-login-verification-information/")
    $null = $DomainTokenList.Rows.Add("unknown","0","13","unknown","webaccel","webaccel:DKIM1; k","unknown","unknown")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","90","12","CA cert authority","Digicert","Digicert=390gn4mx4xy7zthm1rwfr37msfl266d0","digicert.com","https://www.digicert.com/certcentral-support/pending-order-dns-txt-record-dcv-method.htm")
    $null = $DomainTokenList.Rows.Add("unknown","0","12","Mostly associated with co.jp domains.","direct-site-verification","direct-site-verification:dmadwhzghudqtvpo9","unknown","unknown")
    $null = $DomainTokenList.Rows.Add("unknown","0","12","Often associated with Chinese domains.","store.wps.cn","store.wps.cn: 74.113.2.0/23 ip4","unknown","unknown")
    $null = $DomainTokenList.Rows.Add("Security","80","11","Server and network monitoring","thousandeyes","thousandeyes:7b1rkfqf2pogzf3o5bmmxrlsu2p1gpqg","https://www.thousandeyes.com/","https://www.thousandeyes.com/")
    $null = $DomainTokenList.Rows.Add("Email","80","11","ForwardEmail is a free, encrypted, and open-source email forwarding service for custom domains.","forward-email","forward-email=niftylettuce@gmail.com","github ForwardEmail","https://github.com/forwardemail/free-email-forwarding-service")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","50","11","This is a likely a Github service, but I couldn't quickly find an online reference to it.","github-verification","github-verification=first.last@domain.com","github","unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","10","Fortifi is a complete end-to-end cloud based business management platform.","fortifi-domain-verification","fortifi-domain-verification=zza1g9aoz1swtx4279gizim43qfsmb","Fortifi","https://support.fortifi.io/en/kb/article/56/verifying-a-domain-in-fortifi")
    $null = $DomainTokenList.Rows.Add("Unknown","0","10","Appears to be associated with .edu sites.","FuseServer","FusServer=bibliotecas-pf","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Unknown","0","9","Unknown","csverification","csverification:KVj2CUo7CA1oALLMgGsbRu1uMbju2hMrE0ybs9SD","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Cloud Services","50","9","Daum is a South Korean web portal in South Korea, the top second along with Naver. Daum offers many Internet services to web users, including a popular free web-based e-mail, messaging service, forums, shopping, news and webtoon service. ","daum-verification","daum-verification:ApAtknPZ_zQ8oUNy5HrlvQ00","Daum","https://www.daum.net/")
    $null = $DomainTokenList.Rows.Add("Security","50","8","CDN - protecting websites real ip (origin ) from attack","cloudpiercer-verification","cloudpiercer-verification=27638f77f1cb96897693876d8703f50d ","https://cloudpiercer.org/","https://cloudpiercer.org/paper/CloudPiercer.pdf")
    $null = $DomainTokenList.Rows.Add("Unknown","0","8","Unknown","campussuite-domain-verification","campussuite-domain-verification:a6a98d5f33db91e5c2b280336d4fc7799749a9483ed2fd73b64dd159efacf7cb","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Project Management","80","8","Many of the TXT records sampled included the domain and a shared secret. Smartsheet is more than a leading work execution platform. ","smartsheet-site-validation","smartsheet-site-validation=7305a89b175dae9d9c3374f64711a65f03d9c9aba3d3864cb88a2dec029656c4","smartsheet","https://www.smartsheet.com/")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","8","incremented number;sonatype jira account collaboration","OSSRH-","OSSRH-47960","https://oss.sonatype.org/","https://proandroiddev.com/publishing-a-maven-artifact-3-3-step-by-step-instructions-to-mavencentral-publishing-bd661081645d")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","8","Website publishing","rebelmouse","rebelmouse=4a8bac0081ad3f068a403d8adfe347048e5cc631 ","www.rebelmouse.com","https://learning.rebelmouse.com/t/806vn5/dns-settings-for-launch")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","8","Collaboration software","sonatype","sonatype=OSSRH-45437 ","sonatype.com","https://issues.sonatype.org/browse/OSSRH-44268")
    $null = $DomainTokenList.Rows.Add("Collaboration","50","7","Secure online collaboration platform.","keybase-site-verification","keybase-site-verification=Vqh2BYsLdYqXiUncKQNYHpzn9EqTfOLqGs94StKJ0qo","https://keybase.io/","Unknown")
    $null = $DomainTokenList.Rows.Add("Unknown","0","7","An Auth-Code (also called an Authorization Code, Auth-Info Code, or transfer code) is a code created by a registrar to help identify the domain name holder.","Auth-Code","Auth-Code:ZZxqIDFaUL5C8K+FGnby7BavcaRzrnchxZdrobE58QQ=","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Cloud Services","80","7","Company that sells email, web hosting, and online store fronts. Appears to be dutch site.","bHosted.nl","http://www.bhosted.nl:Z5rcO3pfz6pIawnpGxT3cPFswPriu5gOzDHZEta4pKaftdjXAwcyBWxkIu36PZ7y","bhosted","http://www.bhosted.nl")
    $null = $DomainTokenList.Rows.Add("Unknown","0","7","Unknown","CONTROL-BY","CONTROL-BY:2e5be33f-662c-471d-aa49-a652ba9f33c1","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Email","50","7","Used for DomainKeys Identified Mail (DKIM)","e2ma-verification","e2ma-verification:s5n39azqceto","emma","https://support.e2ma.net/s/article/DomainKeys-Identified-Mail-DKIM")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","80","7","marketing and analytics seo","ostrio-domain","ostrio-domain: d8aff443bf4bb53d3a68c1299f60aabb1131d257","ostr.io","https://ostr.io/")
    $null = $DomainTokenList.Rows.Add("Unknown","5","7","Unknown","uwsgi","uwsgi: chtsroq0u9dcuqjks6tdtfd5l2","Unknown","https://uwsgi-docs.readthedocs.io/en/latest/")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","90","7","Email verification and validation service. Used by marketing to send email.","zapier-domain-verification-challenge","zapier-domain-verification-challenge=b0405c86-5747-43ea-b004-ad6fe0ceeb28","zapier.com","zapier.com")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","70","6","Authorized Digital Sellers (website advertising) Just like a robots.txt file on your website, the ads.txt file is created at the root of your domain (e.g. http://domain.com/ads.txt). The file is a standard plain-text file which simply contains a list of ad network domain names, each with an associated ID.","adstxt-domain-verification","adstxt-domain-verification=09825c03d38d60b913406127f4830706fe8bda84e75cd2f1dbc2df06ee51eafa ","adstxt.guru","https://adstxt.guru/blog/what-is-an-ads-txt-file/")
    $null = $DomainTokenList.Rows.Add("Collaboration","90","6","favro is the planning and collaboration app for organizational flow.","favro-verification","favro-verification=JD0U5XYpcNCKudb_2oQxaQ-fuMeZYUyd51nHzBQT_qf ","favro.com","https://help.favro.com/articles/1019946-setting-up-saml-authentication")
    $null = $DomainTokenList.Rows.Add("Cloud Services","50","6","Most sampled instance are associated with .eu and hu (hungary) domains.","nethely-dvc","nethely-dvc:ms99012137","Microsoft DVC Client APIs","https://docs.microsoft.com/en-us/windows/win32/termserv/dvc-client-apis")
    $null = $DomainTokenList.Rows.Add("Unknown","0","6","Unknown","Owner","Owner: cVvCFUPKuN43wtI_QcF_tWiCm5tHVdPO4ihOukvqo3a","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","75","6","Salesforece Marketing Cloud","SFMC-","SFMC-7t1NZyngAxTUR3Tq3AJAV0dXYvT1VcWzKO6Mx1Xz","Salesforece Marketing Cloud","https://help.salesforce.com/articleView?id=mc_gai_faq18.htm&type=5")
    $null = $DomainTokenList.Rows.Add("","0","5","unknown","stripe-verification","stripe-verification=e4d49836a81144c2720bba6b3c5bd51275ea8d9378d9ebd3e4d2f17480f0c565 ","unknown","unknown")
    $null = $DomainTokenList.Rows.Add("Cloud Services","50","5","This service provides an environment for running zone management and record management operations via the API, without the need to build and manage your own DNS server.","nifty-dns-verify","nifty-dns-verify:ms99130056","K5 DNS as a Service. ","https://cloudknowhow.wordpress.com/2017/02/01/introduction-to-managing-k5-dns-as-a-service/")
    $null = $DomainTokenList.Rows.Add("Unknown","0","5","Unknown","Phone","Phone:l528i6v004080k493808j7h9qi0rkr6815ir9yg525c","Unknown","Unknown")
    $null = $DomainTokenList.Rows.Add("Security","80","5","Web application vulnerability scanner.","Probe.ly","Probe.ly:f233db7bb5216438a0bc760d9dc45379be6b5c14cf7e16277cb78e7b88a2e4b4","Probely","https://probely.com/")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","80","4","User story mapping tool.","storiesonboard-verification","storiesonboard-verification=","storiesonboard.com","http://docs.storiesonboard.com/articles/951952-saml-based-sso-authentication")
    $null = $DomainTokenList.Rows.Add("Marketing and Analytics","70","4","marketing  email analytics seo","ahrefs-site-verification","ahrefs-site-verification_ff489c0901e2335eb065bcd52379c5481d7f047979d7bcd4fd1398988a78394e","ahrefs.com","")
    $null = $DomainTokenList.Rows.Add("Certificate Authority","80","4","Provide a number of security services.","Entrust","Entrust:hcD3s8j","Entrust Datacard","https://www.entrustdatacard.com/")
    $null = $DomainTokenList.Rows.Add("Collaboration","70","4","Medium for secure file transfers. This is a Google owned project.","upspin","upspin=b7cc3465df07","upspin","https://upspin.io/")
    $null = $DomainTokenList.Rows.Add("Development and Publishing","90","3","digital publishing","fastly-domain-delegation","fastly-domain-delegation-x2kl6p87n3g5b6FDG-79324-2018-04-10 ","fastly.com","https://docs.fastly.com/guides/basic-setup/adding-cname-records")
    $null = $DomainTokenList.Rows.Add("Security","90","3","Network and app load testing saas","loadmill-challenge","loadmill-challenge=009b5a8530f899fea581482957a9760c ","loadmill.com","https://docs.loadmill.com/setup/domain-verification")

    # Check for known domain validation tokens
    Write-Verbose "[+] Searching DNS TXT records for known domain validation tokens"

    $FingerPrintResults = $TxtRecordList | 
    ForEach-Object {

        # Get target domain and txt record
        $CurrentTxt = $_.txtstring
        $CurrentDomain = $_.domain
        $Command = "powershell -c `"Resolve-DnsName -type txt -name $CurrentDomain`""

        # Set token info to unknown by default
        $TokenFormatSample = "Unknown"
        $TokenService = "Unknown"
        $TokenServiceDescription = "Unknown"
        $TokenServiceCategory = "Unknown"
        $TokenServiceReference = "Unknown"                            
        $Confidence = "Unknown"
        $HowCommon = "Unknown" 

        # Check for finger print                
        $DomainTokenList | 
        ForEach-Object{
            
            # Set a few variables for reuse
            $DomainValidationToken = $_.DomainValidationToken 
            $TokenServiceProvider = $_.name
            $InstancesFromRearch = $_.Count # Instances found out of the Alexa 1 mil at the time of research
                     
            if($CurrentTxt -like "*$DomainValidationToken*")
            {
                # Return matches
                Write-Verbose "[+]   Match: $CurrentDomain uses $TokenServiceProvider"
                 
                # Update token information if found
                $TokenFormatSample = $_.Example
                $TokenService = $_.name
                $TokenServiceDescription = $_.Description
                $TokenServiceCategory = $_.Category   
                $TokenServiceReference = $_.SiteReference                            
                $Confidence = $_.Confidence
                $HowCommon = "$InstancesFromRearch /1mil"                                                               
            }            
        }     
            # Return txt record with any additional info found
                $object = New-Object psobject
                $object | add-member noteproperty Domain $CurrentDomain
                $object | add-member noteproperty TxtRecord $CurrentTxt          
                $object | add-member noteproperty TokenService $TokenService       
                $object | add-member noteproperty TokenServiceDescription $TokenServiceDescription
                $object | add-member noteproperty TokenServiceCategory $TokenServiceCategory
                $object | add-member noteproperty TokenFormatSample $TokenFormatSample                                    
                $object | add-member noteproperty TokenServiceReference $TokenServiceReference                            
                $object | add-member noteproperty Confidence $Confidence 
                $object | add-member noteproperty HowCommon $HowCommon  
                $object | add-member noteproperty Command $Command   
                $object           
    }

    # write to a file
    Write-Verbose "[+] Saving successfully fingerprinted domain validation tokens to $OutfileToken"
    if($FingerPrintResults){
        $FingerPrintResults | Export-Csv -NoTypeInformation $OutfileToken
    }else{
        Write-Verbose "[-] No domain validation token where found in the identified TXT records."
    }
    
    # Print summary
    # Display number of domains, txt records, and known domain validation tokens found
    
    $DomainTXTCount = $TxtRecordList | Measure | Select count -ExpandProperty count        
    $DomainTXTDomainCount = $TxtRecordList | Select domain -Unique | Measure | Select count -ExpandProperty count
    $DomainTXTTokenMatchCount = $FingerPrintResults | Where-Object TokenService -notlike "" | Where TokenService -notlike "unknown" | Measure | Select count -ExpandProperty count
    Write-Verbose "[+] ---------------"
    Write-Verbose "[+] Results Summary"
    Write-Verbose "[+] ---------------"
    Write-Verbose "[+] $DomainTXTDomainCount domains found with non SPF txt records."
    Write-Verbose "[+] $DomainTXTCount non SPF TXT records found."
    Write-Verbose "[+] $DomainTXTTokenMatchCount domain validation token fingerprint matches found."

    # return list of all txt with fingerprint data
    $FingerPrintResults
    
}
