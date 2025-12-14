$Root = Resolve-Path "$PSScriptRoot\..\.."
$env:SOV_ROOT = $Root.Path
$env:RUST_LOG = if ($env:RUST_LOG) { $env:RUST_LOG } else { "info" }

$Bin = Join-Path $env:SOV_ROOT "bin"
$Cfg = Join-Path $env:SOV_ROOT "config"

Write-Host "[i] SOV_ROOT=$($env:SOV_ROOT)"
Write-Host "[i] RUST_LOG=$($env:RUST_LOG)"

