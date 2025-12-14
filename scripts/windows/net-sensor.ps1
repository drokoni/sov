. "$PSScriptRoot\env.ps1"
Write-Host "[+] Starting Net Sensor (Windows)..."
Write-Host "[!] Run PowerShell as Administrator (Npcap required)"
& "$Bin\sov-sensor-net.exe" -c "$Cfg\net-sensor.yaml"

