param(
    [string]$Command,
    [bool]$IsUpdated=0
)

$ErrorActionPreference = "Stop"

# We use this optional boolean flag to always re-download the script,
# unless otherwise specified, and then rerun the newly downloaded version.
#
# This just makes it a lot easier to iterate across computers.
if(!$IsUpdated) {
    Write-Host "Downloading newest version.."
    $RandomId = Get-Random
    Invoke-WebRequest -Headers @{"Cache-Control" = "no-cache"} -Uri "https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/main.ps1?$RandomId" -OutFile main.ps1
    & ".\main.ps1" $Command 1
    Exit
}

# Create the local non-admin user if it does not exist.
$LocalUser = Get-LocalUser | Where-Object { $_.Name -ne "Admin" } | Where-Object { $_.Enabled }
if (!$LocalUser) {
    Write-Host "Creating local user, since none was found."
    New-LocalUser "Bruger" -AccountNeverExpires -NoPassword -UserMayNotChangePassword
}

switch ($Command) {
    "restore" {
        # Enable restore points (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/enable-computerrestore?view=powershell-5.1)
        Enable-ComputerRestore -Drive "C:\"
        Checkpoint-Computer -Description "Before Setup"
    }
    "debloat" {
        # Our non-admin user does not have a password, and we can't initialize
        # their directory without explicitly allowing blank passwords.
        Set-ItemProperty -Path "HKLM:System\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value "0"

        # Initialize local user
        $Creds = New-Object System.Management.Automation.PSCredential($LocalUser, (New-Object System.Security.SecureString))
        Start-Process -WorkingDirectory "C:\" -Filepath "C:\Windows\System32\cmd.exe" -Credential $Creds -ArgumentList "/C"

        & ([scriptblock]::Create((irm "https://debloat.raphi.re/"))) -Sysprep -User $LocalUser
    }
    "apps" {
        # Install browser
        winget install --disable-interactivity --scope machine "Brave.Brave"
        winget install --disable-interactivity --scope machine "Brave.BraveUpdater"
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -Name "ProgId" -Value "BraveURL"
        Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice' -name "ProgId" -Value "BraveURL"

        # Document handling.
        winget install --disable-interactivity --scope machine "TheDocumentFoundation.LibreOffice"
    }
    "update" {
        Install-Module -Name PSWindowsUpdate -Force
        Get-WindowsUpdate
        Install-WindowsUpdate
        winget upgrade --scope machine --all --force
    }
    "activate" {
        irm https://get.activated.win | iex
    }
    "dns" {
        # https://www.elevenforum.com/t/how-to-set-dns-over-https-via-command-prompt.1232/#post-31002
        $i = Get-NetAdapter -Physical
        $i | Get-DnsClientServerAddress -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses '194.242.2.6', '1.1.1.3'
        $i | Get-DnsClientServerAddress -AddressFamily IPv6 | Set-DnsClientServerAddress -ServerAddresses '2a07:e340::6', '2606:4700:4700::1113'
        $i | ForEach-Object {
            $s1 = 'HKLM:System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $_.InterfaceGuid + '\DohInterfaceSettings\Doh\194.242.2.6'; New-Item -Path $s1 -Force | New-ItemProperty -Name "DohFlags" -Value 1 -PropertyType Qword
            $s2 = 'HKLM:System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $_.InterfaceGuid + '\DohInterfaceSettings\Doh\1.1.1.3'; New-Item -Path $s2 -Force  | New-ItemProperty -Name "DohFlags" -Value 1 -PropertyType Qword
            $s3 = 'HKLM:System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $_.InterfaceGuid + '\DohInterfaceSettings\Doh6\2a07:e340::6'; New-Item -Path $s3 -Force | New-ItemProperty -Name "DohFlags" -Value 1 -PropertyType Qword
            $s4 = 'HKLM:System\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $_.InterfaceGuid + '\DohInterfaceSettings\Doh6\2606:4700:4700::1113'; New-Item -Path $s4 -Force  | New-ItemProperty -Name "DohFlags" -Value 1 -PropertyType Qword
        }
        Clear-DnsClientCache;

        Add-DnsClientDohServerAddress -ServerAddress "194.242.2.6" -DohTemplate "https://family.dns.mullvad.net/dns-query" -AllowFallbackToUdp $False -AutoUpgrade $True
        Add-DnsClientDohServerAddress -ServerAddress "2a07:e340::6" -DohTemplate "https://family.dns.mullvad.net/dns-query" -AllowFallbackToUdp $False -AutoUpgrade $True
        Add-DnsClientDohServerAddress -ServerAddress "1.1.1.3" -DohTemplate "https://family.cloudflare-dns.com/dns-query" -AllowFallbackToUdp $False -AutoUpgrade $True
        Add-DnsClientDohServerAddress -ServerAddress "2606:4700:4700::1113" -DohTemplate "https://family.cloudflare-dns.com/dns-query" -AllowFallbackToUdp $False -AutoUpgrade $True

        # https://github.com/austin-lai/Windows_Enable_DNS_over_HTTPS?tab=readme-ov-file#method-2---enable-dns-over-https-using-powershell-command
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\" -Name DNSClient -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\" -Name "DoHPolicy" -Value 3 -PropertyType DWord -Force -ErrorAction Ignore | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\" -Name "DoHPolicy" -Value 3 -Type DWord -Force | Out-Null
        gpupdate.exe /force

        ipconfig /flushdns
    }
    default {
        Write-Host "Unknown Command: $Command"
    }
}