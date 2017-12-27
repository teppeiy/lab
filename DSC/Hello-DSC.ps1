Configuration HelloPowerShellDSC
{
    Node "localhost"
    {
        File HelloDSCFile
        {
            DestinationPath = "$env:HOMEPATH\Desktop\HelloDSCFile.txt"
            Ensure = "Present"
            Type = "File"
            Contents = "Hello　PowerShell　DSC World!!" 
        }
    }
}


$outputPath = "C:\DSC\HelloPowerShellDSC"
HelloPowerShellDSC -OutputPath $outputPath 


Start-DscConfiguration -Path $outputPath -Wait -Verbose

