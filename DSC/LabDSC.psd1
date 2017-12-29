@{ 
    AllNodes    = @( 
        @{ 
            Nodename = "localhost" 
            Role     = "DC"
            #PsDscAllowPlainTextPassword = $true
        }, 
        @{ 
            Nodename = "adfs" 
            Role     = "FS" 
            #PsDscAllowPlainTextPassword = $true
        } 
    )
    NonNodeData = @{
        RetryCount          = 20  
        RetryIntervalSec    = 30
        PowerShellModules   = 'MSOnline', 'AzureAD', 'AzureADPreview'
        AdGroups            = 'HR', 'Sales', 'IT', 'VIP'
        OrganizationalUnits = 'Users', 'FTE', 'Clients'
 
        AdUsers             = @(
            @{
                FirstName         = 'adfs_svc' 
                LastName          = 'For 2008R2'
                UserName          = 'adfs_svc' #SamAccountName
                UserPrincipalName = 'adfs_svc@teppeiy.local'
                Department        = ''
                OU                = 'Users'
                Title             = '' 
            }
            @{
                FirstName         = 'User1' 
                LastName          = '(teppeiy.local)'
                UserName          = 'user1' #SamAccountName
                UserPrincipalName = 'user1@teppeiy.local'
                Department        = 'Sales'
                OU                = 'FTE'
                Title             = 'Sales Manager' 
            }
            @{
                FirstName  = 'User2' 
                LastName   = '(teppeiy.local)'
                UserName   = 'user2' #SamAccountName
                Department = 'HR'
                OU         = 'FTE'
                Title      = 'HR Manager' 
            }
        ) 
    }
}