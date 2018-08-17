$rgs = @("lab3","lab4","lab5")

while(1){
foreach($rg in $rgs){
$Vmname = $rg + "-DC"
Get-AzureRmVMExtension -ResourceGroupName $rg -VMName $VmName -Name CustomScript
$Vmname = $rg + "-FS"
Get-AzureRmVMExtension -ResourceGroupName $rg -VMName $VmName -Name CustomScript
$Vmname = $rg + "-WAP"
Get-AzureRmVMExtension -ResourceGroupName $rg -VMName $VmName -Name CustomScript
Start-Sleep 3
}
}