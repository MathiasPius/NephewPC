param([bool]$IsUpdated=$false)
param([string]$Command)

if(!$IsUpdated) {
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/main.ps1 -OutFile main.ps1
    & ".\main.ps1" --IsUpdated=$true
}
