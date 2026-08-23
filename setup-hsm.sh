#!/usr/bin/env bash
# Gercek SoftHSM2 token'i bu proje icinde baslatir.
# Gercek donanim HSM'e gecmek icin sadece PKCS11_MODULE_PATH'i degistirin -
# uygulama kodu PKCS#11 standardini konustugu icin degismez.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$HERE/softhsm-tokens"
cat > "$HERE/softhsm2.conf" << EOF
directories.tokendir = $HERE/softhsm-tokens
objectstore.backend = file
log.level = ERROR
EOF

export SOFTHSM2_CONF="$HERE/softhsm2.conf"

if [ -z "${HSM_SO_PIN:-}" ] || [ -z "${HSM_PIN:-}" ]; then
  echo "HSM_SO_PIN ve HSM_PIN ortam degiskenlerini ayarlayin, ornek:"
  echo "  HSM_SO_PIN=\$(openssl rand -hex 8) HSM_PIN=\$(openssl rand -hex 8) ./setup-hsm.sh"
  exit 1
fi

softhsm2-util --init-token --slot 0 --label "ISHv4-Vault" --so-pin "$HSM_SO_PIN" --pin "$HSM_PIN"

echo ""
echo "Token hazir. Sunucuyu calistirirken sunlari ayarlayin:"
echo "  export SOFTHSM2_CONF=$HERE/softhsm2.conf"
echo "  export HSM_PIN=<yukarida verdiginiz pin>"
echo "  export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so   # dagitima gore degisebilir"
