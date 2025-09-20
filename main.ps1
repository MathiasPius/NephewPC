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
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/main.ps1 -OutFile main.ps1
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/doh.ps1 -OutFile doh.ps1
    & ".\main.ps1" $Command 1
    Exit
}

# Create the local non-admin user if it does not exist.
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
        cmd.exe /c '.\doh.bat'

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