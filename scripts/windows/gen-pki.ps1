Param(
  [string]$AnalyzerIP = "192.168.0.102",
  [string]$AnalyzerDNS = "sov-analyzer",
  [string]$OutDir = "$PSScriptRoot\..\..\config\pki"
)

$OutDir = (Resolve-Path $OutDir).Path

function Need($cmd) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
    throw "Missing dependency: $cmd. Install OpenSSL (e.g., Git for Windows includes it) and ensure it's in PATH."
  }
}

Need "openssl"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Location $OutDir

$DaysCA = 3650
$DaysLeaf = 825

# DN settings
$C="DE"; $ST="Berlin"; $L="Berlin"; $O="SOV"
$CN_CA="SOV Root CA"

function LeafSubject([string]$CN, [string]$OU) {
  return "/C=$C/ST=$ST/L=$L/O=$O/OU=$OU/CN=$CN"
}

Write-Host "[+] Output dir: $OutDir"
Write-Host "[+] Analyzer SAN: IP=$AnalyzerIP, DNS=$AnalyzerDNS"

# 1) CA
if (!(Test-Path "ca.key") -or !(Test-Path "ca.crt")) {
  Write-Host "[+] Generating CA key/cert..."
  & openssl genrsa -out ca.key 4096
  & openssl req -x509 -new -nodes `
    -key ca.key `
    -sha256 -days $DaysCA `
    -subj "/C=$C/ST=$ST/L=$L/O=$O/OU=CA/CN=$CN_CA" `
    -out ca.crt
} else {
  Write-Host "[=] CA already exists -> skip"
}

# 2) ext files
@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=$AnalyzerDNS
IP.1=$AnalyzerIP
"@ | Set-Content -Encoding ascii "server.ext"

@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
"@ | Set-Content -Encoding ascii "client.ext"

function IssueLeaf([string]$Name, [string]$CN, [string]$OU, [string]$ExtFile) {
  Write-Host "[+] Issuing $Name (CN=$CN, OU=$OU)"

  & openssl genrsa -out "$Name.key" 2048
  & openssl req -new `
    -key "$Name.key" `
    -subj (LeafSubject $CN $OU) `
    -out "$Name.csr"

  & openssl x509 -req `
    -in "$Name.csr" `
    -CA ca.crt -CAkey ca.key -CAcreateserial `
    -out "$Name.crt" `
    -days $DaysLeaf -sha256 `
    -extfile $ExtFile

  Remove-Item -Force "$Name.csr" -ErrorAction SilentlyContinue
}

# 3) server cert
IssueLeaf "analyzer" "sov-analyzer" "Server" "server.ext"

# 4) client certs (OU roles)
IssueLeaf "admin"        "sov-admin"        "SecurityAdmin" "client.ext"
IssueLeaf "operator"     "sov-operator"     "Operator"      "client.ext"
IssueLeaf "sensor-node"  "sov-sensor-node"  "Sensor"        "client.ext"
IssueLeaf "sensor-net"   "sov-sensor-net"   "Sensor"        "client.ext"

Write-Host ""
Write-Host "[+] Done. Files:"
Get-ChildItem $OutDir | Select-Object Name | ForEach-Object { "  - " + $_.Name }
Write-Host ""
Write-Host "[i] Keep *.key secret; distribute ca.crt to all clients."

