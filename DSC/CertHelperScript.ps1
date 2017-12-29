
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

$CertPath = GetOnlyOnePfxCert
if($CertPath -eq $null){ return }
Write-host "Using $CertPath"

if ($pfxPass -eq $null) {$pfxPass = read-host “Enter the pfx password” -assecurestring}
$cert = Import-PfxCertificate -Password $pfxPass -CertStoreLocation "cert:\localmachine\my" -FilePath $CertPath

if($cert -ne $null){
BindCertToWebSite -Certificate $cert
}

# Add sts DNS on DC

# Create adfs_svc account to DC

# Install Cert to ADFS

# Bind Cert with IIS on ADFS

# Run adfsconfig on ADFS

# Install Cert to WAP

# Bind Cert with IIS on WAP

# Add ADFS to HOSTS
# notepad $env:systemroot\System32\drivers\etc\hosts

# Run FspConfigWizard on WAP