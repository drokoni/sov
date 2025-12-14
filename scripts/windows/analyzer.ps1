. "$PSScriptRoot\env.ps1"
Write-Host "[+] Starting Analyzer..."
& "$Bin\sov-analyzer.exe" -c "$Cfg\analyzer.yaml"

