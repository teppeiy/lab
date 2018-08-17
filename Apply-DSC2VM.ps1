
$ResourceGroupName = "lab5"
$VmName = "lab5-dc"

Publish-AzureRmVMDscConfiguration -ConfigurationPath ".\DSC\LabDSC\LabDSC.ps1" -ConfigurationDataPath ".\DSC\LabDSC\LabDSC.psd1" -SkipDependencyDetection -ResourceGroupName "Utilities" -StorageAccountName "teppeiy" -Force

Set-AzureRmVMDscExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -ArchiveBlobName "LabDSC.ps1.zip" -ArchiveResourceGroupName "Utilities" -ArchiveStorageAccountName "teppeiy" -ConfigurationName "DC" -Version "2.76"