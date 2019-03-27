#https://blogs.technet.microsoft.com/paulomarques/2016/03/21/working-with-azure-active-directory-graph-api-from-powershell/

# Work in Progress

function Get-GraphAPIToken
{
       param
       (
              [Parameter(Mandatory=$true)]
              $TenantName,
              [Parameter(Mandatory=$false)]
              $UserName,
              [Parameter(Mandatory=$false)]
              $Password,
              [Parameter(Mandatory=$false)]
              $Credential
       )

       $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
       $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
       [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
       [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
       $clientId = "1950a258-227b-4e31-a9cf-717495945fc2" 
       $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
       $resourceAppIdURI = "https://graph.windows.net"
       $authority = "https://login.windows.net/$TenantName"
       
       #$creds = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList $UserName,$Password
       
       $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
       $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, "auto")
       return $authResult
}


# Full resource list - https://msdn.microsoft.com/library/azure/ad/graph/api/api-catalog

function Get-GraphData{
    param
    (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Tenant,
        [Parameter(Mandatory=$true)]
        [ValidateSet('contacts', 'directoryRoles', 'domains', 'groups', 'subscribedSkus', 'servicePrincipalsByAppId', 'tenantDetails', 'users')]
        $Resource,
        [Parameter(Mandatory=$false)]
        $Extended
    )

    $authHeader = @{

       'Content-Type'='application\json'

       'Authorization'=$Token.CreateAuthorizationHeader()

    }

    $uri = "https://graph.windows.net/$tenant/$($resource)?api-version=1.6"
    $uriPage = "https://graph.windows.net/$tenant/"
    

    #return (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get).value
    $method = (Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get)

    $output = $method.value
    
    #https://blog.kloud.com.au/2016/08/10/enumerating-all-usersgroupscontacts-in-an-azure-tenant-using-powershell-and-the-azure-graph-api-odata-nextlink-paging-function/


    while($method.'odata.nextLink')
        {
            $nextLink = $method.'odata.nextLink'+'&api-version=1.6'

            $method = (Invoke-RestMethod -Uri $uriPage$nextLink -Headers $authHeader -Method Get)
            
            $output += $method.value
        }
    
    return $output
}