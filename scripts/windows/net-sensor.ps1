$Root = Resolve-Path "$PSScriptRoot\..\.."

$env:RUST_LOG = "info"

Write-Host "[+] Starting SOV Network Sensor (Npcap required)"
Write-Host "[!] Run PowerShell as Administrator"

& "$Root\target\release\sov-sensor-net.exe" `
  -c "$Root\config\net-sensor.yaml"

