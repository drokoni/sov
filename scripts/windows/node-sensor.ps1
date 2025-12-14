. "$PSScriptRoot\env.ps1"
Write-Host "[+] Starting Node Sensor (Windows)..."
& "$Bin\sov-sensor-node.exe" -c "$Cfg\node-sensor.yaml" --os windows

