#!/usr/bin/env bash
# Gercek bir CA, sunucu sertifikasi, yetkili istemci sertifikasi ve
# (negatif test icin) sahte bir CA + sahte istemci sertifikasi uretir.
# Private key'ler asla pakette/git repo'sunda tutulmaz - her kurulumda
# taze uretilir. Bu betik Trivy taramasinda bulunan "repo'da private key
# var" bulgusunu duzeltmek icin eklendi (bkz. README).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$HERE/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[1/3] Gercek CA uretiliyor..."
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -subj "/CN=ISHv4-Internal-CA" 2>/dev/null

echo "[2/3] Sunucu sertifikasi uretiliyor..."
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 825 -sha256 2>/dev/null

echo "[3/3] Yetkili istemci sertifikasi uretiliyor..."
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -out client.csr -subj "/CN=ishv4-authorized-client" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 825 -sha256 2>/dev/null

echo "[opsiyonel] Negatif test icin sahte CA + sahte istemci sertifikasi..."
openssl genrsa -out rogue-ca.key 2048 2>/dev/null
openssl req -x509 -new -nodes -key rogue-ca.key -sha256 -days 3650 -out rogue-ca.crt -subj "/CN=Rogue-CA" 2>/dev/null
openssl genrsa -out rogue-client.key 2048 2>/dev/null
openssl req -new -key rogue-client.key -out rogue-client.csr -subj "/CN=fake-client" 2>/dev/null
openssl x509 -req -in rogue-client.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial -out rogue-client.crt -days 825 -sha256 2>/dev/null

rm -f *.csr *.srl
chmod 600 *.key
echo ""
echo "Tamam. Sunucuyu MTLS_PORT=4443 ile calistirip test edin:"
echo "  curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:4443/api/vault/status"
