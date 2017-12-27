# https://docs.microsoft.com/en-us/powershell/module/azure/publish-azurevmdscconfiguration?view=azuresmps-4.0.0
param(
[string] $configurationPath = "C:\Users\teppeiy\source\repos\lab\DSC\LabDSC.ps1",
[string] $configurationDataPath = "C:\Users\teppeiy\source\repos\lab\DSC\LabDSC.psd1",
[string] $configurationArchivePath = "C:\Users\teppeiy\source\repos\lab\DSC\LabDSC.ps1.zip"
)

Publish-AzureVMDscConfiguration -ConfigurationPath $configurationPath -ConfigurationDataPath $configurationDataPath -ConfigurationArchivePath $configurationArchivePath -Force
