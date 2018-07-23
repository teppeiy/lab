Configuration DSCBlockTest
{
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module xPSDesiredStateConfiguration
    Node "localhost"
    {
        WindowsFeature ADDSInstall { 
            Ensure = "Present" 
            Name   = "AD-Domain-Services"
        }
    }
}

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose
