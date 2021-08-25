clear
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$ServerName = $env:COMPUTERNAME
if ($osInfo.ProductType -eq 2) { 
    write-host "Server $ServerName is a Domain Controller so it has no local admins..."
    Import-Module ActiveDirectory
    $DomainAdmins=Get-ADGroupMember -Identity "Domain Admins" | Select-Object name,SamAccountName,objectClass,distinguishedName 
    $EnterpriseAdmins=Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object name,SamAccountName, objectClass,distinguishedName 
    $SchemaAdmins=Get-ADGroupMember -Identity "Schema Admins" | Select-Object name,SamAccountName, objectClass,distinguishedName 
    $OrgManagement=Get-ADGroupMember -Identity "Organization Management" | Select-Object name,SamAccountName, objectClass,distinguishedName 
    write-host "*** DOMAIN ADMINS ***"
    $DomainAdmins | ft
    write-host "*** SCHEMA ADMINS ***"
    $SchemaAdmins | ft
    write-host "*** ENTERPRISE ADMINS ***"
    $EnterpiseAdmins | ft
    write-host "*** ORG MANAGERS ***"
    $OrgManagement | ft
    } else {
    write-host "Server $ServerName is not a Domain Controller, getting list of Admins"
    Foreach ($Member in (Get-LocalGroupMember -Group "Administrators")) {
    $Member

    }
    }


