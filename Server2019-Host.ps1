# Corey Slack, cslack@tabinc.com

# Prompts for a new computer name
Write-Host "Please pick a new computer hostname:" -ForegroundColor Green
Rename-Computer

# Disable SmartScreen Filter
Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

# Sets the script execution policy to "remotesigned"
Set-ExecutionPolicy RemoteSigned
timeout /t -1
Write-Host "Setting execution policy to RemoteSigned" -ForegroundColor Green

# Enables PS remoting
Write-Host "Enabling PS remoting" -ForegroundColor Green
timeout /t -1
Enable-PSRemoting -Force

# Updates the Powershell help files.
Write-Host "Updating PowerShell help files" -ForegroundColor Green
timeout /t -1
Update-Help

# Configures all Windows Firewall profiles to 'notify'
Write-Host "Setting Windows Firewall to allow all traffic" -ForegroundColor Green
timeout /t -1
Set-NetFirewallProfile -All -DefaultInboundAction Allow -DefaultOutboundAction Allow -NotifyOnListen True

# Sets Windows update to 'download and notify for installation'.
Write-Host "Configuring Windows Updates" -ForegroundColor Green
timeout /t -1
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 2
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name AUOptions -Value 3

# Sets EST
Write-Host "Setting time zone to Eastern" -ForegroundColor Green
timeout /t -1
c:\windows\system32\tzutil /s "Eastern Standard Time"

# Sets time to sync with ntp.org
Write-Host "Configuring Windows time" -ForegroundColor Green
timeout /t -1
net stop w32time
w32tm /config /syncfromflags:manual /manualpeerlist:us.pool.ntp.org
net start w32time
w32tm /config /reliable:yes
net stop w32time
net start w32time

# Disables IE ESC
Write-Host "Disabling IE ESC" -ForegroundColor Green
timeout /t -1
Set-ItemProperty -Path “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}” -Name “IsInstalled” -Value 0
Set-ItemProperty -Path “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}” -Name “IsInstalled” -Value 0

# Disables UAC
Write-Host "Disabling UAC" -ForegroundColor Green
timeout /t -1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" -Name EnableLUA -Value 0

# Disables the defrag scheduled task.
Write-Host "Disabling the defrag scheduled task" -ForegroundColor Green
timeout /t -1
Disable-ScheduledTask -TaskName ScheduledDefrag -TaskPath "\Microsoft\Windows\Defrag\"

Write-Host "Disabling the Server Manager scheduled task" -ForegroundColor Green
timeout /t -1
Disable-ScheduledTask -TaskName ServerManager -TaskPath "\Microsoft\Windows\Server Manager"


# Enables RDP
Write-Host "Enabling RDP" -ForegroundColor Green
timeout /t -1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0
Set-NetFirewallRule -DisplayGroup 'Remote Desktop' -Enabled True

# Sets Event logs to 'overwrite as needed'.
Write-Host "Configuring event log settings" -ForegroundColor Green
timeout /t -1
Limit-EventLog -LogName Application,System,Security -OverflowAction OverwriteAsNeeded

# Sets power profile to 'High Performance'
Write-Host "Setting power profile to high performance" -ForegroundColor Green
timeout /t -1
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Disables offloads and RSS
Write-Host "Disabling offloads, RSS, and chimney on NICs" -ForegroundColor Green
timeout /t -1
Set-NetOffloadGlobalSetting -Chimney Disabled
netsh int tcp set global rss=disabled
netsh int tcp set global autotuning=disabled
Disable-NetAdapterRss * 
Disable-NetAdapterLso *
Disable-NetAdapterChecksumOffload * -IpIPv4 -TcpIPv4 -TcpIPv6 -UdpIPv4 -UdpIPv6

# Renames Local Guest Account to 'TABGUEST'
Write-Host "Renaming Local Guest Account" -ForegroundColor Green
timeout /t -1
Rename-LocalUser -Name "guest" -NewName "TABGUEST"

# Sets 'TABGUEST' password
Write-Host "Set password for TABGUEST Account" -ForegroundColor Green
$Password = Read-Host "Enter a new Password" -AsSecureString
$UserAccount = Get-LocalUser -Name "TABGUEST"
$UserAccount | Set-LocalUser -Password $Password

# Disables local 'TABGUEST' account
Write-Host "Disables Local TABGUEST Account" -ForegroundColor Green
timeout /t -1
Get-LocalUser TABGUEST | Disable-LocalUser

#Change CD drive letter
#Write-Host "Changing DVD Drive letter to E " -ForegroundColor Green
#$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "D:"'
#$drv.DriveLetter = "E:"
#$drv.Put() | out-null

# Reboot
Write-Host "Rebooting!!!" -ForegroundColor Green
timeout /t -1
Restart-Computer
