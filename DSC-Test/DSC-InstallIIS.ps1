Configuration DSCBlockTest
{
    #Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
    Import-DscResource -Module xPSDesiredStateConfiguration
    Node "localhost"
    {
        LocalConfigurationManager {            
            DebugMode          = 'All'
            ActionAfterReboot  = 'ContinueConfiguration'           
            RebootNodeIfNeeded = $false
        }
        WindowsFeature installADFS  #install ADFS
        {
            Ensure = "Absent"
            Name   = "ADFS-Federation"
        }
        WindowsFeature NET-Framework-Core {
            Ensure = "Present"
            Name   = "NET-Framework-Core"
        }
    
        xRemoteFile DownloadADFS {
            Uri             = "https://download.microsoft.com/download/F/3/D/F3D66A7E-C974-4A60-B7A5-382A61EB7BC6/RTW/W2K8R2/amd64/AdfsSetup.exe"
            DestinationPath = "C:\Users\Public\Downloads\AdfsSetup.exe"
        }
        
        Script InstallADFS {            
            GetScript  = { @{} }
            SetScript  = 
            {
                $exePath = "C:\Users\Public\Downloads\AdfsSetup.exe"
                $options = "/quiet /LogFile C:\AdfsSetup.log"
                #$options = "/quiet /proxy /LogFile C:\dsc\AdfsSetup.log"
                Invoke-Expression "& $exePath $options"
            }
            TestScript = 
            {
                #return ((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.DisplayName -eq 'Microsoft Azure AD Connect'}) -ine $null)
                return Test-path "C:\Program Files\Active Directory Federation Services 2.0"
            }
            DependsOn  = "[xRemoteFile]DownloadADFS", "[WindowsFeature]NET-Framework-Core", "[WindowsFeature]installADFS"
        }
       
        Script ConfigureADFS {
            SetScript  = {
                # Run setup wizard
                & "$env:ProgramFiles\Active Directory Federation Services 2.0\fsconfig.exe" CreateFarm /ServiceAccount "teppeiy.local\adfs_svc" /ServiceAccountPassword "P@ssw0rd!" /AutoCertRolloverEnabled
            }
            GetScript  = { @{} }
            TestScript = { 
                return Test-Path "$LocalTempDir\$installer" 
            }
            DependsOn  = "[Script]InstallADFS"
            # ServiceAccount needs to be present in Active Direcotry
        }
        
    }
}

# Install-Module -Name xPSDesiredStateConfiguration -force

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose -force
