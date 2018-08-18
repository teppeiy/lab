#https://docs.microsoft.com/en-us/powershell/dsc/troubleshooting#using-xdscdiagnostics-to-analyze-dsc-logs

(Get-DscConfigurationStatus).ResourcesNotInDesiredState

Get-WinEvent -LogName "Microsoft-Windows-Dsc/Operational"