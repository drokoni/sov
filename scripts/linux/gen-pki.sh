#!/usr/bin/env bash
set -euo pipefail

# ---------- settings ----------
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/config/pki"

# Подставь свой IP анализатора (Arch), например 192.168.0.102
ANALYZER_IP="${ANALYZER_IP:-192.168.0.102}"
ANALYZER_DNS="${ANALYZER_DNS:-sov-analyzer}"

DAYS_CA=3650
DAYS_LEAF=825

# DN наполнение (можешь менять под себя)
C="DE"
ST="Berlin"
L="Berlin"
O="SOV"
CN_CA="SOV Root CA"
CN_ANALYZER="sov-analyzer"
CN_ADMIN="sov-admin"
CN_OPERATOR="sov-operator"
CN_SENSOR_NODE="sov-sensor-node"
CN_SENSOR_NET="sov-sensor-net"

# ---------- helpers ----------
need() { command -v "$1" >/dev/null 2>&1 || {
    echo "[-] Missing dependency: $1"
    exit 1
}; }

leaf_subject() {
    # $1=CN, $2=OU
    echo "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=$2/CN=$1"
}

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

need openssl

echo "[+] Output dir: $OUT_DIR"
echo "[+] Analyzer SAN: IP=${ANALYZER_IP}, DNS=${ANALYZER_DNS}"

# ---------- 1) CA ----------
if [[ ! -f ca.key || ! -f ca.crt ]]; then
    echo "[+] Generating CA key/cert..."
    openssl genrsa -out ca.key 4096
    openssl req -x509 -new -nodes \
        -key ca.key \
        -sha256 -days "${DAYS_CA}" \
        -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=CA/CN=${CN_CA}" \
        -out ca.crt
else
    echo "[=] CA already exists (ca.key/ca.crt) -> skip"
fi

# ---------- 2) OpenSSL ext files ----------
cat >server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1=${ANALYZER_DNS}
IP.1=${ANALYZER_IP}
EOF

cat >client.ext <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

# ---------- 3) function to issue leaf cert ----------
issue_leaf() {
    # $1=name prefix, $2=CN, $3=OU, $4=extfile
    local name="$1"
    local cn="$2"
    local ou="$3"
    local ext="$4"

    echo "[+] Issuing ${name} (CN=${cn}, OU=${ou})"

    openssl genrsa -out "${name}.key" 2048
    openssl req -new \
        -key "${name}.key" \
        -subj "$(leaf_subject "${cn}" "${ou}")" \
        -out "${name}.csr"

    openssl x509 -req \
        -in "${name}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${name}.crt" \
        -days "${DAYS_LEAF}" -sha256 \
        -extfile "${ext}"

    rm -f "${name}.csr"
}

# ---------- 4) server cert ----------
issue_leaf "analyzer" "${CN_ANALYZER}" "Server" "server.ext"

# ---------- 5) client certs (OU roles!) ----------
issue_leaf "admin" "${CN_ADMIN}" "SecurityAdmin" "client.ext"
issue_leaf "operator" "${CN_OPERATOR}" "Operator" "client.ext"
issue_leaf "sensor-node" "${CN_SENSOR_NODE}" "Sensor" "client.ext"
issue_leaf "sensor-net" "${CN_SENSOR_NET}" "Sensor" "client.ext"

# ---------- 6) print summary ----------
echo
echo "[+] Done. Files:"
ls -1 "${OUT_DIR}" | sed 's/^/  - /'

echo
echo "[i] Important:"
echo "  - Keep *.key secret"
echo "  - Distribute ca.crt to all clients"
echo "  - Use analyzer.crt/analyzer.key on server"
echo "  - Use admin/operator/sensor-*.crt + key on clients"
