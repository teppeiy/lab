<#
.SYNOPSIS
This is ADDSDeployment wrapper module for downlevel OS (Windows Sever 2008R2).
Do not import this module on Windows Server 2012R2 or above which has native ADDSDeployment.

.DESCRIPTION
This is designed to support PowerShell DSC xADDomain in xActiveDirectory which calls ADDSDeployment. If xADDomain is used on Windows Server 2008R2, it fails with ADDSDeployment module not found error, but with this module, it will success for new Forest Creation scenario only unless other functions such as Install-ADDSDomain is implemented.

.NOTES
General notes

https://technet.microsoft.com/ja-jp/library/hh974719(v=wps.630).aspx
https://support.microsoft.com/en-us/help/947034/how-to-use-unattended-mode-to-install-and-remove-active-directory-doma
#>

# Creates a read-only domain controller (RODC) account that can be used to install an RODC in Active Directory.
function Add-ADDSReadOnlyDomainControllerAccount {
    param()
}

# Installs a new Active Directory domain configuration.
function  Install-ADDSDomain {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Install-ADDSDomain is yet to be supported"
}
# Installs a domain controller in Active Directory.
function Install-ADDSDomainController {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Install-ADDSDomainController is yet to be supported"
}

# Installs a new Active Directory forest configuration.
function  Install-ADDSForest {
    [CmdletBinding()]
    param
    (
        [parameter(mandatory = $true)]
        [string] $DomainName,
        [switch] $CreateDnsDelegation,
        [string] $DatabasePath,
        [PSCredential] $DnsDelegationCredential,
        [string] $DomainMode = 4,
        [string] $DomainNetbiosName,
        [switch] $Force,
        [string] $ForestMode = 4,
        [switch] $InstallDns,
        [string] $LogPath,
        [switch] $NoDnsOnNetwork,
        [switch] $NoRebootOnCompletion,
        [SecureString] $SafeModeAdministratorPassword,
        [switch] $SkipAutoConfigureDns,
        [switch] $SkipPreChecks,
        [string] $SysvolPath,
        [switch] $Confirm,
        [switch] $WhatIf
    )
    $log = "c:\dsc\install-addsforest_wrapper.log"
    New-Item -ItemType File $log -Force

    $unattendedFile = "c:\dsc\unattended.txt"
    New-Item -ItemType File $unattendedFile -Force
        
    "Creating $unattendedFile" >> $log

    $netbiosName = $DomainName.Split(".")[0]
    $RebootOnCompletion = !$NoRebootOnCompletion

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SafeModeAdministratorPassword)
    $UnsecureSafeModeAdminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    "[DCInstall]" >> $unattendedFile
    "NewDomain=Forest" >> $unattendedFile
    "ReplicaOrNewDomain=Domain" >> $unattendedFile
    "SafeModeAdminPassword=$UnsecureSafeModeAdminPassword" >> $unattendedFile
    if ($RebootOnCompletion) {
        "RebootOnCompletion=Yes" >> $unattendedFile
    }
    else {
        "RebootOnCompletion=No" >> $unattendedFile 
    }
    if ($PSBoundParameters.ContainsKey('DnsDelegationCredential')) {
        "CreateDNSDelegation=Yes" >> $unattendedFile
        "DNSDelegationUserName=$DnsDelegationCredential.UserName" >> $unattendedFile
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SafeModeAdministratorPassword)
        $UnsecureDNSDelegationPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        "DNSDelegationPassword=$UnsecureDNSDelegationPassword"  >> $unattendedFile
    }
    if ($PSBoundParameters.ContainsKey('DatabasePath')) {
        "DatabasePath=$DatabasePath" >> $unattendedFile
    }
    if ($PSBoundParameters.ContainsKey('LogPath')) {
        "LogPath=$LogPath" >> $unattendedFile 
    }
    if ($PSBoundParameters.ContainsKey('SysvolPath')) {
        "SysvolPath=$SysvolPath" >> $unattendedFile 
    }

    "NewDomainDNSName=$DomainName" >> $unattendedFile
    if ($PSBoundParameters.ContainsKey('DomainNetbiosName')) {
        "DomainNetbiosName=$netbiosName" >> $unattendedFile
    }
    "InstallDNS=Yes" >> $unattendedFile
    
    "ForestLevel=$ForestMode" >> $unattendedFile
    "DomainLevel=$DomainMode" >> $unattendedFile

    "Unattended file created based on $PSBoundParameters" >> $log
    "Promoting DC" >> $log

    & dcpromo /unattend:$unattendedFile
}

# Runs the prerequisites (only) for installing a domain controller in Active Directory.
function Test-ADDSDomainControllerInstallation {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Test-ADDSDomainControllerInstallation is yet to be supported"
}
# Runs the prerequisites (only) for uninstalling a domain controller in Active Directory.
function Test-ADDSDomainControllerUninstallation {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Test-ADDSDomainControllerUninstallation is yet to be supported"
}
# Runs the prerequisites (only) for installing a new Active Directory domain configuration.
function Test-ADDSDomainInstallation {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Test-ADDSDomainInstallation is yet to be supported"
}

# Runs the prerequisites (only) for installing a new forest in Active Directory.
function Test-ADDSForestInstallation {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Test-ADDSForestInstallation is yet to be supported"
}
# Runs the prerequisites (only) for adding a read-only domain controller (RODC) account.
function Test-ADDSReadOnlyDomainControllerAccountCreation {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Test-ADDSReadOnlyDomainControllerAccountCreation is yet to be supported"
}
# Uninstalls a domain controller in Active Directory.
function Uninstall-ADDSDomainController {
    [CmdletBinding()]
    param()
    Write-Verbose "ADDSDeployment Downlevel Server Support Wrapper: Uninstall-ADDSDomainController is yet to be supported"
}

Export-ModuleMember Install-ADDSForest
# Export-ModuleMember Install-ADDSDomain