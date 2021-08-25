$services=get-service | ? { $_.name -like "MSExchange*" -or $_.name -like "w3svc" -or $_.name -like "iisadmin" -or $_.name -like "winmgmt" -or $_.name -like "fms" -and $_.name -notlike "*imap4*" -and $_.name -notlike "*pop3*"}; foreach ($service in $services) { 
    write-host $service
    if ($service.StartType -eq "Disabled") {
        write-host "- disabled, enabling" -ForegroundColor Red 
        set-service $service.name -StartupType automatic
        start-service $service.name 
    } else {
        if ($service.status -ne "Running") {
            write-host "- enabled, but not running; starting" -ForegroundColor red
            start-service $service.name 
        } else {
            write-host "- enabled and running" -ForegroundColor green 
        }
    }
}

write-host "Rebooting... "
shutdown /r /f /t 30
