Configuration DSCBlockTest
{
    Import-DscResource -Module ComputerManagementDsc
    Node "localhost"
    {
        PowerShellExecutionPolicy ExecutionPolicy 
        { 
            ExecutionPolicy = 'RemoteSigned'
            ExecutionPolicyScope = 'LocalMachine'
        } 
    }
}

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose
