# Enable restore points (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/enable-computerrestore?view=powershell-5.1)
Enable-ComputerRestore -Drive "C:\"
Checkpoint-Computer -Description "Before Setup"
