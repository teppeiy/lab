Publish-AzureRmVMDscConfiguration -ConfigurationPath ".\LabDSC\LabDSC.ps1" -ConfigurationDataPath ".\LabDSC\LabDSC.psd1" -ResourceGroupName "Utilities" -StorageAccountName "teppeiy" -Force

$ResourceGroupName = "lab3"
$VmName = "lab3-dc"

$cred = Get-Credential
$configurationArguments = @{
    domainName = "teppeiy.local"
    safemodeAdministratorCred = $cred
    domainCred = $cred
    NewADUserCred = $cred
}

Set-AzureRmVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -ArchiveBlobName "LabDSC.ps1.zip" -ConfigurationArgument $configurationArguments -ArchiveResourceGroupName "Utilities" -ArchiveStorageAccountName "teppeiy" -ConfigurationName "DC" -Version "2.76"

#################################################
# FS
#################################################
$ResourceGroupName = "lab5"
$VmName = "lab5-fs"

$cred = Get-Credential
$configurationArguments = @{
    domainName = "teppeiy.local"
    domainCred = $cred
}

Set-AzureRmVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -ArchiveBlobName "LabDSC.ps1.zip" -ConfigurationArgument $configurationArguments -ArchiveResourceGroupName "Utilities" -ArchiveStorageAccountName "teppeiy" -ConfigurationName "FS" -Version "2.76"

