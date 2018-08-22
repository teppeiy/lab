
function GetOnlyOnePfxCert {
    param(
        [string]$CertDir = "$env:userprofile\Desktop"
    )
    $certs = Get-ChildItem -Path $CertDir -File | ? {$_ -like '*.pfx'}
    if ($certs.count -gt 1) {
        Write-host "Multiple *.pfx found in $CertDir"
        return $null
    }
    return $certs.FullName
}
function Import-PfxCertificate {
    param(
        [SecureString]$Password,
        [String]$FilePath,
        [String]$CertStoreLocation = "cert:\CurrentUser\my"
    )
    $pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
    $pfx.import($FilePath, $Password, “Exportable,PersistKeySet”)
    $store = new-object System.Security.Cryptography.X509Certificates.X509Store($CertStoreLocation.Split('\')[2], $CertStoreLocation.Split('\')[1])
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]”ReadWrite”)
    $store.add($pfx)
    $store.close()
    return $pfx
}
function BindCertToWebSite {
    param(
        [string]$SiteName = "Default Web Site",
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Import-Module WebAdministration
    New-WebBinding -Name $SiteName -IPAddress "*" -Port 443 -Protocol HTTPS
    
    # get the web binding of the site
    $binding = Get-WebBinding -Name $SiteName -Protocol "HTTPS"  
    # set the ssl certificate
    $binding.AddSslCertificate($Certificate.GetCertHashString(), "MY")
}

function AddStsDnsToHostsFile {
    param(
        [string]$IpAddress,
        [string]$HostName
    )
    $file = "$env:windir\System32\drivers\etc\hosts"
    "$IpAddress`t$HostName" | Add-Content -PassThru $file
}

$mode = Read-Host "Enter 0 for configuring ADFS, other for WAP:"
Write-host "Make sure you have only one SSL cert (*.pfx) on your desktop"


if ($mode -eq '0') {
    # Install Cert to ADFS

    $CertPath = GetOnlyOnePfxCert
    if ($CertPath -eq $null) { return }
    Write-host "Using $CertPath"

    if ($pfxPass -eq $null) {$pfxPass = read-host “Enter the pfx password” -assecurestring}
    $cert = Import-PfxCertificate -Password $pfxPass -CertStoreLocation "cert:\localmachine\my" -FilePath $CertPath

    # Bind Cert with IIS on ADFS
    if ($cert -ne $null) {
        BindCertToWebSite -Certificate $cert
    }

    # Add sts DNS on DC
    Read-Host "Did you add DNS record for internal access in DNS?"
    # Create adfs_svc account to DC
    Read-Host "Did you add ADFS service account in domain?"

    # Run adfsconfig on ADFS
    Write-host "Please run ADFSConfigWizard"
}
else {
    # Install Cert to WAP
    $CertPath = GetOnlyOnePfxCert
    if ($CertPath -eq $null) { return }
    Write-host "Using $CertPath"

    if ($pfxPass -eq $null) {$pfxPass = read-host “Enter the pfx password” -assecurestring}
    $cert = Import-PfxCertificate -Password $pfxPass -CertStoreLocation "cert:\localmachine\my" -FilePath $CertPath

    # Bind Cert with IIS on WAP
    if ($cert -ne $null) {
        BindCertToWebSite -Certificate $cert
    }

    # Add ADFS to HOSTS
    $IpAddress = "10.0.0.5"
    $StsHostName = "sts.teppeiy.local"
    AddStsDnsToHostsFile -IpAddress $IpAddress -HostName $StsHostName

    # Run FspConfigWizard on WAP
    Write-host "Please run ADFSConfigWizard"
}