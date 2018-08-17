#Compress-Archive -Path .\LabDSC\* -Update -DestinationPath .\LabDSC.ps1.zip

Publish-AzureRmVMDscConfiguration -ConfigurationPath ".\LabDSC\LabDSC.ps1" -ConfigurationDataPath ".\LabDSC\LabDSC.psd1" -SkipDependencyDetection -OutputArchivePath ".\LabDSC.ps1.zip" -Force


