function GetFilesInDirectory {
    [CmdletBinding()]
    param(        
        [parameter(mandatory = $true)]
        [string] $Path,
        [array] $FileExtensions = @(),
        [string] $IgnoreFileName = ".ignore"
    )
    $ignoreFiles = @()
    try {
        $ignoreFiles = Get-Content -Path "$Path\$IgnoreFileName"
    }
    catch {
        Write-verbose "$Path\$IgnoreFileName not found"
    }
    return @(Get-ChildItem -File -Path $Path | where {($ignoreFiles -notcontains $_.Name) -and ($_.Extension -in $FileExtensions) })
}
function GetDirectories {
    [CmdletBinding()]
    param(
        [parameter(mandatory = $true)]
        [string] $Path,
        [string] $IgnoreFileName = ".ignore"
    )
    $ignoreFiles = @()
    try {
        $ignoreFiles = Get-Content -Path "$Path\$IgnoreFileName"
    }
    catch {
        Write-verbose "$Path\$IgnoreFileName not found"
    }
    return @(Get-ChildItem -Directory -Path $Path | where {($ignoreFiles -notcontains $_.Name)})
}

# https://docs.microsoft.com/en-us/powershell/module/azure/publish-azurevmdscconfiguration?view=azuresmps-4.0.0
function dsc {
    [CmdletBinding()]
    param(
        [string] $DscPath = "DSC"
    )

    $dirs = GetDirectories -Path ".\$DscPath" -IgnoreFileName ".ignore" -Verbose

    if ($dirs.Count -ne 1) {
        Write-Verbose "Currently not supporting multiple directories."
        return
    }

    $fileExtensions = @(".ps1", ".psd1")
    $files = GetFilesInDirectory -Path $dirs.FullName -FileExtensions $fileExtensions -IgnoreFileName ".ignore" -Verbose

    $configurationPath = $dirs.FullName + "\" + $dirs.Name + ".ps1"
    $configurationDataPath = $dirs.FullName + "\" + $dirs.Name + ".psd1"
    $configurationArchivePath = $dirs.FullName + ".ps1.zip"

    $ps1 = @($files | where {$_.Extension -eq ".ps1"})
    $psd1 = @($files | where {$_.Extension -eq ".psd1"})
    Write-Verbose ("ps1:{0}, psd1{1}" -f $ps1.Count, $psd1.Count)

    if ($ps1.Count -eq 0) {
        Write-Output "No ps1 file found"
        return
    }
    elseif ($ps1.Count -eq 1) {
        # Only 1 ps1 file
        if ($psd1.Count -eq 0) {
            # No psd1 file
            Publish-AzureVMDscConfiguration -ConfigurationPath $configurationPath -ConfigurationArchivePath $configurationArchivePath -Force -Verbose
            return
        }
        elseif ($psd1.Count -eq 1) {
            # Both ps1 and psd1 file are 1
            Publish-AzureVMDscConfiguration -ConfigurationPath $configurationPath -ConfigurationDataPath $configurationDataPath -ConfigurationArchivePath $configurationArchivePath -Force -Verbose
            return
        }
        else {
            # Do nothing
        }
    }
    else {
        $additionalPath = @()
        ($ps1 | Where-object {$_.FullName -ne $configurationPath}) | ForEach{$additionalPath += $_.FullName}
        ($psd1 | Where-object {$_.FullName -ne $configurationDataPath}) | ForEach{$additionalPath += $_.FullName}

        Publish-AzureVMDscConfiguration -ConfigurationPath $configurationPath -ConfigurationDataPath $configurationDataPath -AdditionalPath $additionalPath -ConfigurationArchivePath $configurationArchivePath -Force
    }
}

dsc