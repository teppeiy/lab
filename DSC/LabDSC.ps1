configuration DC {
    param
    (
        [Parameter(Mandatory)] 
        [string]$domainName,
        [Parameter(Mandatory)] 
        [pscredential]$safemodeAdministratorCred, 
        [Parameter(Mandatory)] 
        [pscredential]$domainCred, 
        [Parameter] 
        [pscredential]$DNSDelegationCred, 
        [Parameter(Mandatory)]
        [pscredential]$NewADUserCred 
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xActiveDirectory

    Node $AllNodes.Where{$_.Role -eq "DC"}.Nodename 
    {
        LocalConfigurationManager {
            DebugMode          = 'All'
            RebootNodeIfNeeded = $false
        }
        WindowsFeature ADDSInstall { 
            Ensure = "Present" 
            Name   = "AD-Domain-Services"
        }
        WindowsFeature RSAT-AD-AdminCenter {
            Ensure = "Present"
            Name   = "RSAT-AD-AdminCenter"
        }
        WindowsFeature RSAT-ADDS {
            Ensure = "Present"
            Name   = "RSAT-ADDS"
        }
        WindowsFeature RSAT-AD-PowerShell {
            Ensure = "Present"
            Name   = "RSAT-AD-PowerShell"
        }
        WindowsFeature RSAT-AD-Tools {
            Ensure = "Present"
            Name   = "RSAT-AD-Tools"
        }
        
        Script DeployADDSDeploymentWrapper {
            SetScript  = {
                $modulePath = "C:\Program Files\WindowsPowerShell\Modules\ADDSDeployment\"
                if(!(Test-Path -Path $modulePath)){
                    New-item -Path $modulePath -ItemType Directory
                    }
                Invoke-WebRequest -Uri "https://raw.githubusercontent.com/teppeiy/lab/master/DSC/ADDSDeployment/ADDSDeployment.psm1" -OutFile "$modulePath\ADDSDeployment.psm1"
                Import-Module -Name "ADDSDeployment"
            }
            GetScript  = { @{} }
            TestScript = { 
                $key = Get-Module -Name "ADDSDeployment" -ListAvailable
                return ($key -ine $null)
            }
        }

        xADDomain ADDomain { 
            DomainName                    = $domainName 
            DomainAdministratorCredential = $domainCred 
            SafemodeAdministratorPassword = $safemodeAdministratorCred 
            #DnsDelegationCredential = $DNSDelegationCred 
            DependsOn                     = "[WindowsFeature]ADDSInstall", "[Script]DeployADDSDeploymentWrapper"
        }
        
        @($ConfigurationData.NonNodeData.ADGroups).foreach( {
                xADGroup $_ {
                    Ensure    = 'Present'
                    GroupName = $_
                    Path      = ("OU={0},DC={1},DC={2}" -f 'FTE', ($domainName -split '\.')[0], ($domainName -split '\.')[1])
                    DependsOn = '[xADDomain]ADDomain', "[xADOrganizationalUnit]FTE"
                }
            })
 
        @($ConfigurationData.NonNodeData.OrganizationalUnits).foreach( {
                xADOrganizationalUnit $_ {
                    Ensure    = 'Present'
                    Name      = ($_ -replace '-')
                    Path      = ('DC={0},DC={1}' -f ($domainName -split '\.')[0], ($domainName -split '\.')[1])
                    DependsOn = '[xADDomain]ADDomain'
                }
            })
 
        @($ConfigurationData.NonNodeData.ADUsers).foreach( {
                xADUser $_.UserName {
                    Ensure            = 'Present'
                    DomainName        = $domainName
                    GivenName         = $_.FirstName
                    SurName           = $_.LastName
                    UserName          = $_.UserName
                    UserPrincipalName = $_.UserPrincipalName
                    Department        = $_.Department
                    Path              = ("OU={0},DC={1},DC={2}" -f $_.OU, ($domainName -split '\.')[0], ($domainName -split '\.')[1])
                    JobTitle          = $_.Title
                    Password          = $NewADUserCred
                    DependsOn         = '[xADDomain]ADDomain', ("[xADOrganizationalUnit]{0}" -f $_.OU)
                }
            })
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
                    @{site = "%SystemRoot%\system32\dsa.msc"; name = "AD Users and Computers"; icon = "%SystemRoot%\system32\dsadmin.dll, 0"},
                    @{site = "%SystemRoot%\system32\domain.msc"; name = "AD Domains and Trusts"; icon = "%SystemRoot%\system32\domadmin.dll, 0"},
                    @{site = "%SystemRoot%\system32\dnsmgmt.msc"; name = "DNS"; icon = "%SystemRoot%\system32\dnsmgr.dll, 0"},
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0"}
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
            Uri = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
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
                return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
            }
            DependsOn = "[xRemoteFile]DownloadAzureADConnect"
        }
    }
}
configuration FS {
    param
    (
        [Parameter(Mandatory)] 
        [string]$domainName,
        [Parameter(Mandatory)] 
        [pscredential]$domainCred
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xActiveDirectory, xComputerManagement, xPendingReboot

    Node 'localhost'
    {
        LocalConfigurationManager {
            DebugMode          = 'All'
            RebootNodeIfNeeded = $true
        }
        xPendingReboot Reboot1
        {
            # Make sure to refresh DNS Server address
            Name = "RebootServer"        
        }
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $DomainName 
            DomainUserCredential= $domainCreds
            RetryCount = $ConfigData.NonNodeData.RetryIntervalSec
            RetryIntervalSec = $ConfigData.NonNodeData.RetryIntervalSec
            DependsOn = "[xPendingReboot]Reboot1"
        }
        xComputer JoinDomain
        {
            Name          = $env:COMPUTERNAME 
            DomainName    = $domainName 
            Credential    = $domainCred  # Credential to join to domain
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
        xPendingReboot Reboot2
        { 
            Name = "RebootServer"
            DependsOn = "[xComputer]JoinDomain"
        }
        WindowsFeature installADFS  #install ADFS
        {
            Ensure = "Present"
            Name   = "ADFS-Federation"
            DependsOn = "[xPendingReboot]Reboot2"
        }
        <#
        WindowsFeature RSAT-AD-AdminCenter {
            Ensure = "Present"
            Name   = "RSAT-AD-AdminCenter"
        }
        WindowsFeature RSAT-ADDS {
            Ensure = "Present"
            Name   = "RSAT-ADDS"
        }
        WindowsFeature RSAT-AD-PowerShell {
            Ensure = "Present"
            Name   = "RSAT-AD-PowerShell"
        }
        WindowsFeature RSAT-AD-Tools {
            Ensure = "Present"
            Name   = "RSAT-AD-Tools"
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
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0"}
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
            Uri = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
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
                return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
            }
            DependsOn = "[xRemoteFile]DownloadAzureADConnect"
        }
    }
}

configuration FS-DOWNLEVEL {
    param
    (
        [Parameter(Mandatory)] 
        [string]$domainName,
        [Parameter(Mandatory)] 
        [pscredential]$domainCred
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xActiveDirectory, xComputerManagement, xPendingReboot

    Node 'localhost'
    {
        LocalConfigurationManager {
            DebugMode          = 'All'
            RebootNodeIfNeeded = $true
        }
        xPendingReboot Reboot1
        {
            # Make sure to refresh DNS Server address
            Name = "RebootServer"        
        }
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $DomainName 
            DomainUserCredential= $domainCreds
            RetryCount = $ConfigData.NonNodeData.RetryIntervalSec
            RetryIntervalSec = $ConfigData.NonNodeData.RetryIntervalSec
            DependsOn = "[xPendingReboot]Reboot1"
        }
        xComputer JoinDomain
        {
            Name          = $env:COMPUTERNAME 
            DomainName    = $domainName 
            Credential    = $domainCred  # Credential to join to domain
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }
        xPendingReboot Reboot2
        { 
            Name = "RebootServer"
            DependsOn = "[xComputer]JoinDomain"
        }
        WindowsFeature installADFS  #install ADFS
        {
            Ensure = "Present"
            Name   = "ADFS-Federation"
            DependsOn = "[xPendingReboot]Reboot2"
        }
        <#
        WindowsFeature RSAT-AD-AdminCenter {
            Ensure = "Present"
            Name   = "RSAT-AD-AdminCenter"
        }
        WindowsFeature RSAT-ADDS {
            Ensure = "Present"
            Name   = "RSAT-ADDS"
        }
        WindowsFeature RSAT-AD-PowerShell {
            Ensure = "Present"
            Name   = "RSAT-AD-PowerShell"
        }
        WindowsFeature RSAT-AD-Tools {
            Ensure = "Present"
            Name   = "RSAT-AD-Tools"
        }
       #>
       WindowsFeature NET-Framework-Core {
            Ensure = "Present"
            Name   = "NET-Framework-Core"
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
                $options = "/quiet /LogFile C:\dsc\AdfsSetup.log"
                #$options = "/quiet /proxy /LogFile C:\dsc\AdfsSetup.log"
                Invoke-Expression "& $exePath $options"
            }
            TestScript = 
            {
                #return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
                return Test-path "C:\Program Files\Active Directory Federation Services 2.0"
            }
            DependsOn  = "[xRemoteFile]DownloadADFS", "[WindowsFeature]NET-Framework-Core"
        }
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
                    @{site = "%windir%\system32\services.msc"; name = "Services"; icon = "%windir%\system32\filemgmt.dll, 0"}
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
            Uri = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
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
                return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
            }
            DependsOn = "[xRemoteFile]DownloadAzureADConnect"
        }
    }
}

Configuration WAP
{
    param
    (
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }

	    WindowsFeature WebAppProxy
        {
            Ensure = "Present"
            Name = "Web-Application-Proxy"
        }

        WindowsFeature Tools 
        {
            Ensure = "Present"
            Name = "RSAT-RemoteAccess"
            IncludeAllSubFeature = $true
        }

        WindowsFeature MoreTools 
        {
            Ensure = "Present"
            Name = "RSAT-AD-PowerShell"
            IncludeAllSubFeature = $true
        }

        WindowsFeature Telnet
        {
            Ensure = "Present"
            Name = "Telnet-Client"
        }
    }
}

Configuration WAP-DOWNLEVEL
{
    param
    (
    )
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module PSDesiredStateConfiguration, xPSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }
        <#
	    WindowsFeature WebAppProxy
        {
            Ensure = "Present"
            Name = "Web-Application-Proxy"
        }
        
        WindowsFeature Tools 
        {
            Ensure = "Present"
            Name = "RSAT-RemoteAccess"
            IncludeAllSubFeature = $true
        }
        #>
        WindowsFeature MoreTools 
        {
            Ensure = "Present"
            Name = "RSAT-AD-PowerShell"
            IncludeAllSubFeature = $true
        }

        WindowsFeature Telnet
        {
            Ensure = "Present"
            Name = "Telnet-Client"
        }
        WindowsFeature NET-Framework-Core {
            Ensure = "Present"
            Name   = "NET-Framework-Core"
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
                #$options = "/quiet /LogFile C:\dsc\AdfsSetup.log"
                $options = "/quiet /proxy /LogFile C:\dsc\AdfsSetup.log"
                Invoke-Expression "& $exePath $options"
            }
            TestScript = 
            {
                #return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
                return Test-path "C:\Program Files\Active Directory Federation Services 2.0"
            }
            DependsOn  = "[xRemoteFile]DownloadADFS", "[WindowsFeature]NET-Framework-Core"
        }
    }
}
