# Powershell policy
# Set-ExecutionPolicy Unrestricted -force

# Enable RDP for Azure AD Account
# net localgroup "Remote Desktop Users" /add "Authenticated Users"

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install Git
choco install git -y
choco install git-credential-manager-for-windows -y


# Install Tools
choco install microsoft-edge -y
choco install googlechrome -y
choco install office365proplus -y
choco install microsoft-teams -y
choco install visualstudiocode -y

choco install firefox -y
choco install fiddler -y --install-arguments "/D=C:\Program Files\Fiddler"
choco install notepadplusplus -y
choco install opera -y
choco install putty -y
#choco install rdcman -y

choco install tor-browser -y
choco install nodejs.install -y
choco install sysinternals -y
choco install networkmonitor -y
choco install vcredist2013 -y
choco install microsoftazurestorageexplorer -y
#choco install airserver -y
choco install 7zip.install -y

#choco install visualstudio2017enterprise -y

choco install googlejapaneseinput -y

# Install PowerShell Modules
#Install-Module AzureRM -Force
#Import-Module AzureRM
#Install-Module -Name AzureADPreview -Force
#Import-Module -Name AzureADPreview
#Install-Module -Name MSOnline -Force
#Import-Module -Name MSOnline
#Install-Module -Name MSCloudIdUtils
#Install-Module -Name Microsoft.Azure.ActiveDirectory.PIM.PSModule -Force
#Install-Module -Name Azure-Security-Center -Force
#Import-Module -Name Azure-Security-Center

#Get-Module -Name Microsoft.Online.SharePoint.PowerShell -ListAvailable | Select Name,Version
#Install-Module -Name Microsoft.Online.SharePoint.PowerShell
# SfB Powershell https://www.microsoft.com/en-us/download/details.aspx?id=39366
