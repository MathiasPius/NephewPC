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
    "setup" {
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
    default {
        Write-Host "Unknown Command: $Command"
    }
}