param(
    [string]$Command,
    [bool]$IsUpdated=0
)

if(!$IsUpdated) {
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/MathiasPius/NephewPC/refs/heads/main/main.ps1 -OutFile main.ps1
    & ".\main.ps1" $Command 1
}
