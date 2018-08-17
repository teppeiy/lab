
$fileUris = @('https://raw.githubusercontent.com/teppeiy/lab/master/DSC/SetPowershellExecutionPolicy.ps1')



$ResourceGroupName = "lab8"
$VmName = "lab8-dc"

Set-AzureRmVMCustomScriptExtension -ResourceGroupName $ResourceGroupName -VMName $VmName -FileUri $fileUris -Run "powershell -ExecutionPolicy Unrestricted -File SetPowershellExcutionPolicy.ps1" -Location "Southeast Asia" -Name "SetPowershellExecutionPolicy"

