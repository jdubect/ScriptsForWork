﻿$HostServer=$true
        (get-wmiobject win32_share -computername $serverName).path | foreach {
        $driveLetter = $_.split(":")[0]
        if (($driveLetter) -and ($driveLetterArray -notcontains $driveLetter)) {
            $driveLetterArray += $driveLetter
            }
        } 
    foreach ($letter in $driveLetterArray) {
        $letter = $letter + ":\"
        $deviceID = (gwmi win32_volume -computername $serverName | Where-Object {$_.Name -eq $letter}).deviceID
        $deviceID = $deviceID.TrimStart("\\?\")
        $deviceID = "Win32_Volume.DeviceID=`"\\\\?\\" + $deviceID + "\`""
        $shadowQuery = gwmi win32_shadowstorage -computername $serverName | Where-Object {$_.Volume -eq $deviceID}
        if ($shadowQuery) {
            write-host "  - Volume shadow enabled on drive $letter" -f green
        } else {
            write-host "  - Volume shadow NOT enabled on drive $letter" -f red
            }
        }
    $obj = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('machine',$computer)
    if ($obj.ValidateCredentials("tabadmin", $tabadminpw)) { write-host "  - tabadmin checks out" -f green } else { write-host "  - tabadmin check failed" -f red }
    $AppErrors=(get-eventlog -entrytype Warning,Error -logname application -After (Get-Date).AddDays(-7)).count
    $SecErrors=(Get-EventLog -logname security -EntryType FailureAudit -After (Get-Date).AddDays(-7)).count
    $EventFailed=$false
    if (($SysErrors -gt 10) -or ($AppErrors -gt 10) -or ($SecErrors -gt 10)) {
        write-host "  - There have been $SysErrors system log errors, $Apperrors application log errors and $SecErrors security log failures" -f red 
        } else {
        write-host "  - There have been $SysErrors system log errors, $Apperrors application log errors and $SecErrors security log failures" -f green
        }
    }
    if (Get-ItemProperty $AutoUpdatePath -Name NoAutoUpdate) {
        $NoAutoUpdate = Get-ItemProperty $AutoUpdatePath -Name NoAutoUpdate | Select-Object NoAutoUpdate | ft -HideTableHeaders | out-string
        $NoAutoUpdate=$NoAutoUpdate.trim()
        } else { $NoAutoUpdate="unset" }
    $AUOptions = Get-ItemProperty $AutoUpdatePath -Name AUOptions | Select-Object AUOptions | ft -HideTableHeaders | out-string
    $AUOptions=$AUOptions.trim()
    If ($NoAutoUpdate -eq "1") { write-host "  - automatic updates are disabled" -f green 
        } else {
        if ($noAutoUpdate -eq "unset") { write-host "  - automatic updates are not defined!" -f red } else { write-host "  - automatic updates are possibly enabled!" -f red }
        }
    switch ($AUOptions) {
        1 { write-host "  - auto-update set to disabled" -f green }
        2 { write-host "  - auto-update set to notify" -f green }
        3 { write-host "  - auto-update set to download & notify" -f green }
        4 { write-host "  - auto-update set to download and install" -f red }
        }