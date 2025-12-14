$Root = Resolve-Path "$PSScriptRoot\..\.."

$env:RUST_LOG = "info"

Write-Host "[+] Starting SOV Analyzer"
Write-Host "[+] Root: $Root"

& "$Root\target\release\sov-analyzer.exe" `
  -c "$Root\config\analyzer.yaml"

