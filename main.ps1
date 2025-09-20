param(
    [string]$Command,
    [bool]$IsUpdated=0
)

if(!$IsUpdated) {
    Write-Host "Downloading newest version.."
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/main.ps1 -OutFile main.ps1
    & ".\main.ps1" $Command 1
    Exit
}

$LocalUser = Get-LocalUser | Where-Object { $_.Name -ne "Admin" }
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
        & ([scriptblock]::Create((irm "https://debloat.raphi.re/"))) -Sysprep -User $LocalUser
    }
    "apps" {
        # Install browser
        winget install --disable-interactivity --scope machine "Brave.Brave"
        winget install --disable-interactivity --scope machine "Brave.BraveUpdater"
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
        # Mullvad Family DNS: https://mullvad.net/en/help/dns-over-https-and-dns-over-tls#win11
        Add-DnsClientDohServerAddress -ServerAddress 194.242.2.6 -DohTemplate "https://family.dns.mullvad.net" -AllowFallbackToUdp $False -AutoUpgrade $True
        ipconfig /flushdns

        # https://github.com/austin-lai/Windows_Enable_DNS_over_HTTPS?tab=readme-ov-file#method-2---enable-dns-over-https-using-powershell-command
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\" -Name DNSClient -ErrorAction Ignore | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\" -Name "DoHPolicy" -Value 3 -PropertyType DWord -Force -ErrorAction Ignore | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient\" -Name "DoHPolicy" -Value 3 -Type DWord -Force | Out-Null
        gpupdate.exe /force
    }
    default {
        Write-Host "Unknown Command: $Command"
    }
}