Configuration DSCBlockTest
{
    Import-DscResource -Module PSDesiredStateConfiguration, xWindowsUpdate
    Node "localhost"
    {
        xHotfix HotfixInstall
        {
            # https://support.microsoft.com/en-us/help/2790338/description-of-update-rollup-3-for-active-directory-federation-service
            
            Ensure = "Present"
            Path = "http://hotfixv4.microsoft.com/Windows%207/Windows%20Server2008%20R2%20SP1/sp2/Fix421449/7600/free/456227_intl_x64_zip.exe"
            Id = "KB2790338"
        }
    }
}

$outputPath = "C:\DSC\DSCBlockTest"
DSCBlockTest -OutputPath $outputPath 

Start-DscConfiguration -Path $outputPath -Wait -Verbose


<#
PowerShell DSC resource MSFT_xWindowsUpdate  failed to execute Set-TargetResource functionality with error message: 
Could not install the windows update. Details are stored in the log C:\Windows\TEMP\tmp20B8.tmp.etl . Error message is 
 Windows update  could not be installed because of error 2147944030 "Data of this type is not supported." (Command line: ""C:\Windows\system32\wusa.exe" 
"C:\ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\MSFT_xWindowsUpdate\456227_intl_x64_zip.exe" /quiet /norestart /log:"C:\Windows\TEMP\tmp20B8.tmp.etl" ")  .
Please look at Windows Update error codes here for more information - http://technet.microsoft.com/en-us/library/dd939837(WS.10).aspx . 
    + CategoryInfo          : InvalidOperation: (:) [], CimException
    + FullyQualifiedErrorId : ProviderOperationExecutionFailure
    + PSComputerName        : localhost

Eventlog
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-WUSA" Guid="{09608C12-C1DA-4104-A6FE-B959CF57560A}" /> 
  <EventID>3</EventID> 
  <Version>0</Version> 
  <Level>2</Level> 
  <Task>0</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8000000000000000</Keywords> 
  <TimeCreated SystemTime="2017-12-31T08:17:33.522526800Z" /> 
  <EventRecordID>889</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="3824" ThreadID="3820" /> 
  <Channel>Setup</Channel> 
  <Computer>LAB4-FS.teppeiy.local</Computer> 
  <Security UserID="S-1-5-18" /> 
  </System>
- <EventData>
  <Data Name="UpdateTitle" /> 
  <Data Name="ErrorCode">2147944030</Data> 
  <Data Name="ErrorString">Data of this type is not supported.</Data> 
  <Data Name="CommandLine">"C:\Windows\system32\wusa.exe" "C:\ProgramData\Microsoft\Windows\PowerShell\Configuration\BuiltinProvCache\MSFT_xWindowsUpdate\456227_intl_x64_zip.exe" /quiet /norestart /log:"C:\Windows\TEMP\tmp20B8.tmp.etl"</Data> 
  </EventData>
  </Event>

#>