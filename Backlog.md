# Backlog

## Both
* WAP NSG doesn't open HTTP/S
* ADFS ip needs to be static?
* DNS zone creation automation on DC
* Public DNS record creation automation for WAP, maybe ATM?
* Cert and tenant quick setup

* Permanent 2008R2 farm

## 2008R2 farm
* FIXED: adfssetup.exe sometimes stops, manybe needs dependenty? ConfigurationMode  = 'ApplyAndAutoCorrect' on LCM fixed the issue
* Rollup needed to be installed - https://support.microsoft.com/en-us/help/2790338/description-of-update-rollup-3-for-active-directory-federation-service
* Streamlined support for cert install, adfs setup, CertHelper doesnt support binding config override
* ADFS wizard needs to be run under domain account creds
* ADFS service account creation on DC?
* WAP server needs DNS record for STS, need to edit HOSTS file prior to WAP config wizard

## 2012R2 farm
* WRM needs to be setup for WAP config  
https://docs.microsoft.com/en-us/azure/active-directory/connect/active-directory-aadconnect-prerequisites#windows-remote-management


    