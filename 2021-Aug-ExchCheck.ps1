$ErrorActionPreference="SilentlyContinue"
$CVE202134473="no"
$CVE202134523="no"
$CVE202131207="no"
$KB5001779="no"
$KB5003435="no"
$ExchVer=GCM exsetup | %{$_.Fileversioninfo} | ft ProductVersion -HideTableHeaders | Out-String
$ExchVer=$ExchVer.Trim()
$ExchInstDir=$env:exchangeinstallpath
clear
Function DownloadCU {
    write-host "- Exchange build $ExchVer"
    switch -wildcard ($ExchVer) {
            "15.00*" { write-host "- Exchange 2013 was detected, downloading CU23"
            if (test-path c:\windows\ltsvc\scripts\exch2013cu23.exe) { write-host "- It seemse CU23 maybe already downloaded to c:\windows\ltsvc\scripts\Exch2013cu23.exe" }
            else { invoke-webrequest -Uri https://download.microsoft.com/download/7/F/D/7FDCC96C-26C0-4D49-B5DB-5A8B36935903/Exchange2013-x64-cu23.exe -OutFile c:\windows\ltsvc\scripts\Exch2013CU23.exe }
            if (test-path c:\windows\ltsvc\scripts\exch2013cu23.exe) { write-host "- file download appears to be done" }
            else { write-host "- ERROR: File download appears to have failed." -ForegroundColor Red ; exit }
            }
            "15.01*" { write-host "- Exchange 2016 was detected, downloading CU21"
            if (test-path c:\windows\ltsvc\scripts\exch2016cu21.iso) { write-host "- It seemse CU21 maybe already downloaded to c:\windows\ltsvc\scripts\Exch2016CU21.iso" }
            else { invoke-webrequest -Uri https://download.microsoft.com/download/7/d/5/7d5c319b-510b-4a2c-a77a-099c6f30ab54/ExchangeServer2016-x64-CU21.ISO -OutFile c:\windows\ltsvc\scripts\exch2016cu21.iso }
            if (test-path c:\windows\ltsvc\scripts\exch2016cu21.iso) { write-host "- file download appears to be done" }
            else { write-host "- ERROR: File download appears to have failed." -ForegroundColor Red ; exit }
            }
            "15.02*" { write-host "- Exchange 2019 was detected, downloading CU10"
            if (test-path c:\windows\ltsvc\scripts\exch2019cu10.iso) { write-host "- It seemse CU10 maybe already downloaded to c:\windows\ltsvc\scripts\Exch2019cu10.iso" }
            else { invoke-webrequest -Uri https://download.microsoft.com/download/7/3/f/73f75f9e-e7fd-4cb0-a2fc-405cbb800f2d/ExchangeServer2019-x64-CU10.ISO -OutFile c:\windows\ltsvc\scripts\2019cu10.iso }
            if (test-path c:\windows\ltsvc\scripts\exch2019cu10.iso) { write-host "- file download appears to be done" }
            else { write-host "- ERROR: File download appears to have failed." -ForegroundColor Red ; exit }
            }
    }
}

Function DownloadKB5001779 {
    if (Test-Path c:\windows\ltsvc\scripts\kb5001779.msp) { write-host "- KB5001779 already downloaded" }
    else {
    write-host "- Downloading KB5001779"
    Invoke-WebRequest -uri $KB5001779 -OutFile c:\windows\ltsvc\scripts\KB5001779.msp }
    if (test-path c:\windows\ltsvc\scripts\KB5001779.msp) { write-host "- file download appears to be done" }
    else { write-host "- ERROR: File download appears to have failed. -ForegroundColor Red" }
    }
Function DownloadKB5003435 {
    if (Test-Path c:\windows\ltsvc\scripts\kb5003435.msp) { write-host "- KB5003435 already downloaded" }
    else {
    write-host "-Downloading KB5003435"
    Invoke-WebRequest -Uri $KB5003435 -OutFile c:\windows\ltsvc\scripts\KB5003435.msp }
    if (test-path c:\windows\ltsvc\scripts\KB5003435.msp) { write-host "- file download appears to be done" }
    else { write-host "- ERROR: File download appears to have failed. -ForegroundColor Red" }
    }

write-host "Performing ASPX Check for active webshells in c:\inetpub\wwwroot\aspnet_client ..."
$Shells=Get-ChildItem c:\inetpub\wwwroot\aspnet_client\ -recurse -filter  "*.aspx"
Foreach ($shell in $shells) {
    write-host "- WARN: Webshell file found and remove attempted - c:\inetpub\wwwroot\aspnet_client\$shell" -ForegroundColor Red
    remove-item c:\inetpub\wwwroot\aspnet_client\$shell
    }
write-host "Performing ASPX Check for active webshells in C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Current ..."
$Shells=Get-ChildItem 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Current\' -recurse -filter  "*.aspx"
Foreach ($shell in $shells) {
    write-host "- WARN: Webshell file found and remove attempted - c:\inetpub\wwwroot\aspnet_client\$shell" -ForegroundColor Red
    remove-item 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Current\'$shell
    }
write-host "Exchange installed at $ExchInstDir"

Switch -wildcard ($ExchVer) {
    "15.02.0922*" { 
        write-host "VERSION: Exchange 2019 CU10 found, should be patched but will check anyway"}
    "15.02.0858*" { 
        write-host "VERSION: Exchange 2019 CU9 found" 
        $KB5001779="https://download.microsoft.com/download/2/a/e/2aee7e6c-ef35-4db2-b401-93f367f769df/Exchange2019-KB5001779-x64-en.msp"
        $KB5003435="https://download.microsoft.com/download/3/3/2/332845f4-72ec-4b60-b2ee-c30cc44434c5/Exchange2019-KB5003435-x64-en.msp"
        }
    "15.02.0792*" { 
        write-host "VERSION: Exchange 2019 CU8 found"
        $KB5001779="https://download.microsoft.com/download/c/b/b/cbbfd5a7-c33c-4e5e-94c7-aaaf92cbf5b5/Exchange2019-KB5001779-x64-en.msp"
        $KB5003435="https://download.microsoft.com/download/f/5/8/f5868796-a30d-4891-bd6a-36638d4fc700/Exchange2019-KB5003435-x64-en.msp"
        }
    "15.01.2308*" { 
        write-host "VERSION: Exchange 2016 CU21 found, should be patched but will check anyway" }
    "15.01.2242*" { 
        write-host "VERSION: Exchange 2016 CU20 found" 
        $KB5001779="https://download.microsoft.com/download/2/c/b/2cbd4e0b-282b-4cc2-b8be-8bc4c288b505/Exchange2016-KB5001779-x64-en.msp"
        $KB5003435="https://download.microsoft.com/download/b/8/c/b8c73a56-8347-4b0b-97dd-4a84dbf138a3/Exchange2016-KB5003435-x64-en.msp"
        }
    "15.01.2176*" { 
        write-host "VERSION: Exchange 2016 CU19 found" 
        $KB5001779="https://download.microsoft.com/download/4/c/a/4cae76c5-129f-4d76-8756-59c677e07a73/Exchange2016-KB5001779-x64-en.msp"
        $KB5003435="https://download.microsoft.com/download/3/2/3/323a68cd-8841-407e-8dc5-899b3b204ce5/Exchange2016-KB5003435-x64-en.msp"
        }
    "15.00.1497*" { 
        write-host "VERSION: Exchange 2013 CU23 found" 
        $KB5001779="https://download.microsoft.com/download/d/8/5/d85bb76c-34ad-4897-bbce-cb7f132454dc/Exchange2013-KB5001779-x64-en.msp"
        $KB5003435="https://download.microsoft.com/download/6/d/b/6db9b354-306c-4ad6-8cc2-c07ca896a4b7/Exchange2013-KB5003435-x64-en.msp"
        }
    default {
        write-host "ERROR: Exchange build is not supported for direct patching $ExchVer" -ForegroundColor red
        DownloadCU
        Exit
        }
    }


#write-host "Downloading most recent HealthChecker from MS GitHub..."
#Remove-Item C:\windows\ltsvc\scripts\HealthChecker.ps1 -Force
#invoke-webrequest -uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1" -outfile C:\windows\ltsvc\scripts\HealthChecker.ps1
write-host "Executing script and dumping to C:\Windows\LTSvc\Scripts\HealthCheckerOutput.txt"
powershell.exe "C:\windows\ltsvc\scripts\healthchecker.ps1" > "c:\windows\ltsvc\scripts\HealthCheckerOutput.txt"

write-host "Checking to see if script ran OK"
$ScriptOk=select-string -path "c:\windows\ltsvc\scripts\HealthCheckerOutput.txt" -pattern "Exchange Web App Pools"
if ($ScriptOk -ne $null) { write-host "- Found text in output text file whch indicates script ran" -ForegroundColor Green } 
    else { 
    write-host "- ERROR: Text file seems to indicate script did not run" -ForegroundColor Red; Exit }

write-host "Checking for CVE-2021-34473 to be patched"
$CVE202134473=select-string -path "c:\windows\ltsvc\scripts\HealthCheckerOutput.txt" -Pattern "CVE-2021-34473"
if ($CVE202134473 -eq $null) { write-host "- Did not find CVE listed in output text file" -ForegroundColor Green } 
    else { 
    write-host "- WARN: CVE found in text file which indicates this system is vulnerable" -ForegroundColor Red
    DownloadKB5001779 }

write-host "Checking for CVE-2021-34523 to be patched"
$CVE202134523=select-string -path "c:\windows\ltsvc\scripts\HealthCheckerOutput.txt" -Pattern "CVE-2021-34523"
if ($CVE202134523 -eq $null) { write-host "- Did not find CVE listed in output text file" -ForegroundColor Green } 
    else { 
    write-host "- WARN: CVE found in text file which indicates this system is vulnerable" -ForegroundColor Red 
    DownloadKB5001779 }

write-host "Checking for CVE-2021-31207 to be patched"
$CVE202131207=select-string -path "c:\windows\ltsvc\scripts\HealthCheckerOutput.txt" -Pattern "CVE-2021-31207"
if ($CVE202131207 -eq $null) { write-host "- Did not find CVE listed in output text file" -ForegroundColor Green } 
    else { 
    write-host "- WARN: CVE found in text file which indicates this system is vulnerable" -ForegroundColor Red 
    DownloadKB5003435 }