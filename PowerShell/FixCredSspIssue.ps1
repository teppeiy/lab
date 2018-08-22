# https://support.microsoft.com/en-gb/help/4295591/credssp-encryption-oracle-remediation-error-when-to-rdp-to-azure-vm#sac-script

# Run this on the VM

#Create a download location
md c:\temp

##Download the KB file
# for 1703
$source = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2018/05/windows10.0-kb4103731-x64_209b6a1aa4080f1da0773d8515ff63b8eca55159.msu"
$destination = "c:\temp\windows10.0-kb4103731-x64_209b6a1aa4080f1da0773d8515ff63b8eca55159.msu"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($source,$destination)

#Install the KB
expand -F:* $destination C:\temp\
dism /ONLINE /add-package /packagepath:"c:\temp\Windows10.0-KB4103731-x64.cab"

#Add the vulnerability key to allow unpatched clients
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2

#Restart the VM to complete the installations/settings
shutdown /r /t 0 /f
