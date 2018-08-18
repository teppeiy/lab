configuration FS-DOWNLEVEL {
    param
    (
        [Parameter(Mandatory)] 
        [string]$domainName,
        [Parameter(Mandatory)] 
        [pscredential]$domainCred
    )
    #Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
    Import-DscResource -Module PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xActiveDirectory, xComputerManagement, xPendingReboot,xWindowsUpdate

    Node 'localhost'
    {
        LocalConfigurationManager {
            DebugMode          = 'All'
            RebootNodeIfNeeded = $true
        }
        xPendingReboot Reboot1 {
            # Make sure to refresh DNS Server address
            Name = "RebootServer"        
        }
        xWaitForADDomain DscForestWait { 
            DomainName           = $DomainName 
            DomainUserCredential = $domainCreds
            RetryCount           = $ConfigData.NonNodeData.RetryIntervalSec
            RetryIntervalSec     = $ConfigData.NonNodeData.RetryIntervalSec
            DependsOn            = "[xPendingReboot]Reboot1"
        }
        xComputer JoinDomain {
            Name       = $env:COMPUTERNAME 
            DomainName = $domainName 
            Credential = $domainCred  # Credential to join to domain
            DependsOn  = "[xWaitForADDomain]DscForestWait"
        }
        xPendingReboot Reboot2 { 
            Name      = "RebootServer"
            DependsOn = "[xComputer]JoinDomain"
        }
        <#
        WindowsFeatureSet RSATInstall
        {
            Name = @("RSAT-AD-AdminCenter", "RSAT-ADDS", "RSAT-AD-PowerShell","RSAT-AD-Tools")
            Ensure = 'Present'
        } 
       #>
        WindowsFeature NET-Framework-Core {
            Ensure = "Present"
            Name   = "NET-Framework-Core"
        }
        xPendingReboot Reboot3 { 
            Name      = "RebootServer"
            DependsOn = "[WindowsFeature]NET-Framework-Core"
        }
        xRemoteFile DownloadADFS {
            Uri             = "https://download.microsoft.com/download/F/3/D/F3D66A7E-C974-4A60-B7A5-382A61EB7BC6/RTW/W2K8R2/amd64/AdfsSetup.exe"
            DestinationPath = "C:\Users\Public\Downloads\AdfsSetup.exe"
        }
        
        Script InstallADFS {            
            GetScript  = { @{} }
            SetScript  = 
            {
                $exePath = "C:\Users\Public\Downloads\AdfsSetup.exe"
                $options = "/quiet /LogFile C:\AdfsSetup.log"
                #$options = "/quiet /proxy /LogFile C:\dsc\AdfsSetup.log"
                Invoke-Expression "& $exePath $options"
            }
            TestScript = 
            {
                #return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
                return Test-path "C:\Program Files\Active Directory Federation Services 2.0"
            }
            DependsOn  = "[xRemoteFile]DownloadADFS", "[WindowsFeature]NET-Framework-Core", "[xPendingReboot]Reboot3"
        }
<#
        xHotfix HotfixInstall
        {
            # https://support.microsoft.com/en-us/help/2790338/description-of-update-rollup-3-for-active-directory-federation-service
            
            Ensure = "Present"
            Path = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix421449/7600/free/456227_intl_x64_zip.exe"
            Id = "KB2790338"
            DependsOn = "[Script]InstallADFS"
        }
#>
        foreach ($m in @($ConfigurationData.NonNodeData.PowerShellModules)) {
            Script $m {
                SetScript  = {
                    Install-Module -Name $using:m -AllowClobber -Force
                }

                GetScript  = { @{} }
                TestScript = { 
                    $key = Get-Module -Name $using:m -ListAvailable
                    return ($key -ine $null)
                }
            }
        }

        Script DeployLinks {
            SetScript  = {
                $WshShell = New-Object -comObject WScript.Shell
                $dt = "C:\Users\Public\Desktop\"
                $links = @(
                    @{site = "%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"; name = "PowerShell ISE"; icon = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe, 0"},
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0"},
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0"},
                    @{site = "%ProgramFiles%\Active Directory Federation Services 2.0\Microsoft.IdentityServer.msc"; name = "AD FS 2.0 Management"; icon = "%ProgramFiles%\Active Directory Federation Services 2.0\Microsoft.IdentityServer.NativeResources.dll, 0"},
                    @{site = "%windir%\system32\inetsrv\InetMgr.exe"; name = "Internet Information Services (IIS) Manager"; icon = "%windir%\system32\inetsrv\InetMgr.exe, 0"}
                )

                foreach ($link in $links) {
                    $Shortcut = $WshShell.CreateShortcut("$($dt)$($link.name).lnk")
                    $Shortcut.TargetPath = $link.site
                    $Shortcut.IconLocation = $link.icon
                    $Shortcut.Save()
                }
            }
            GetScript  = { @{} }
            TestScript = {
                $icons = Get-ChildItem -Path "C:\Users\Public\Desktop\"
                $result = 0
                foreach ($i in $icons) {
                    if (($i.name).endswith('.lnk')) {
                        $result++
                    }
                }
                return ($result -gt 0)
            }
        }
        xRemoteFile DownloadAzureADConnect {
            Uri             = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
            DestinationPath = "C:\Users\Public\Downloads\AzureADConnect.msi"
        }
        Script InstallAzureADConnect {            
            GetScript  = { @{} }
            SetScript  = 
            {
                $MSIPath = "C:\Users\Public\Downloads\AzureADConnect.msi"
                Invoke-Expression "& $env:SystemRoot\system32\msiexec.exe /i $MSIPath /qn /passive /forcerestart"
            }
            TestScript = 
            {
                return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
            }
            DependsOn  = "[xRemoteFile]DownloadAzureADConnect"
        }
        xRemoteFile ConfigurationScript {
            Uri             = "https://raw.githubusercontent.com/teppeiy/lab/master/DSC/CertHelperScript.ps1"
            DestinationPath = "C:\Users\Public\Desktop\CertHelperScript.ps1"
        }
    }
}


$configData = @{ 
    AllNodes    = @( 
        @{ 
            Nodename = "localhost" 
            Role     = "DC"
            PsDscAllowPlainTextPassword = $true
        }, 
        @{ 
            Nodename = "adfs" 
            Role     = "FS" 
            PsDscAllowPlainTextPassword = $true
        } 
    )
    NonNodeData = @{
        RetryCount          = 20  
        RetryIntervalSec    = 30
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

$outputPath = "C:\DSC\FS-DOWNLEVEL"
FS-DOWNLEVEL -OutputPath $outputPath -ConfigurationData $configData

Start-DscConfiguration -Path $outputPath -Wait -Verbose

