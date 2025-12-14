$Root = Resolve-Path "$PSScriptRoot\..\.."

$env:RUST_LOG = "info"

Write-Host "[+] Starting SOV Node Sensor (Windows Event Log)"

& "$Root\target\release\sov-sensor-node.exe" `
  -c "$Root\config\node-sensor.yaml" `
  --os windows

