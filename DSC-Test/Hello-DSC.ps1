Configuration DSCBlockTest
{
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module xPSDesiredStateConfiguration
    Node "localhost"
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'                    
            RebootNodeIfNeeded = $false
        }
        xRemoteFile DownloadADFS {
            Uri = "https://download.microsoft.com/download/F/3/D/F3D66A7E-C974-4A60-B7A5-382A61EB7BC6/RTW/W2K8R2/amd64/AdfsSetup.exe"
            DestinationPath = "C:\Users\Public\Downloads\AzureADConnect.msi"
        }
        Script InstallADFS{            
            GetScript  = { @{} }
            SetScript  = 
            {
                $MSIPath = "C:\Users\Public\Downloads\AzureADConnect.msi"
                Invoke-Expression "& $env:SystemRoot\system32\msiexec.exe /i $MSIPath /qn /passive /forcerestart"
            }
            TestScript = 
            {
                return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
            }
            DependsOn = "[xRemoteFile]DownloadADFS"
        }
    }
}

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose
