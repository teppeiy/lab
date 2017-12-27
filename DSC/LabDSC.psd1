@{ 
    AllNodes    = @( 
        @{ 
            Nodename                    = "localhost" 
            Role                        = "DC" 
            #DomainName = "teppeiy.local"
            RetryCount                  = 20  
            RetryIntervalSec            = 30  
            PsDscAllowPlainTextPassword = $true
        }, 
        @{ 
            Nodename         = "adfs" 
            Role             = "ADFS" 
            #DomainName = "teppeiy.local" 
            RetryCount       = 20  
            RetryIntervalSec = 30  
            #PsDscAllowPlainTextPassword = $true
        } 
    )
    NonNodeData = @{
        PowerShellModules   = 'MSOnline', 'AzureAD', 'AzureADPreview'
        AdGroups            = 'HR', 'Sales', 'IT', 'VIP'
        OrganizationalUnits = 'FTE', 'Clients'
 
        AdUsers             = @(
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