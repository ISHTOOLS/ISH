#!/usr/bin/env bash
# Gercek yuk testi - autocannon ile, gercek AES-256-GCM sifreleme
# endpoint'ine karsi. Iki senaryo test edilir:
#  1. Asiri yuklenme (rate limiter'in gercekten calistigini kanitlar)
#  2. Surdurulebilir hiz (gercek kripto performansini olcer)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=${PORT:-4099}

command -v autocannon >/dev/null || { echo "npm install -g autocannon"; exit 1; }

echo "[1/4] Sunucu baslatiliyor..."
rm -rf "$HERE/data-loadtest" && mkdir -p "$HERE/data-loadtest"
ISHV4_DATA_DIR=data-loadtest PORT=$PORT node "$HERE/server.js" > /tmp/ishv4-loadtest.log 2>&1 &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null" EXIT
sleep 1.5

echo "[2/4] Vault hazirlaniyor..."
INIT=$(curl -s -X POST localhost:$PORT/api/vault/init -H 'Content-Type: application/json' -d '{"thresholdK":2,"totalSharesN":3}')
echo "$INIT" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for s in d['shares'][:2]:
    print(json.dumps({'shareIndex':s['index'],'shareHex':s['shareHex']}))
" | while read -r line; do
  curl -s -X POST localhost:$PORT/api/vault/unseal -H 'Content-Type: application/json' -d "$line" > /dev/null
done
curl -s -X POST localhost:$PORT/api/kms/keys -H 'Content-Type: application/json' -d '{"alias":"loadtest"}' > /dev/null

echo ""
echo "[3/4] SENARYO 1: Asiri yukleme (20 baglanti, sinirsiz hiz, 4sn)"
echo "      Beklenen: rate limiter cogu istegi 429 ile reddetmeli (bu ISTENEN davranistir)"
autocannon -d 4 -c 20 -m POST -H "Content-Type: application/json" \
  -b '{"alias":"loadtest","plaintext":"overload test payload"}' \
  --renderStatusCodes \
  http://localhost:$PORT/api/kms/encrypt

echo ""
echo "[4/4] SENARYO 2: Surdurulebilir hiz (1 baglanti, 7 istek/sn, 4sn)"
echo "      Beklenen: neredeyse tum istekler 200 donmeli (gercek kripto verimi)"
autocannon -d 4 -c 1 -R 7 -m POST -H "Content-Type: application/json" \
  -b '{"alias":"loadtest","plaintext":"sustainable rate test payload"}' \
  --renderStatusCodes \
  http://localhost:$PORT/api/kms/encrypt

rm -rf "$HERE/data-loadtest"
