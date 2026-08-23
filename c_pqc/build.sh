#!/usr/bin/env bash
# Gercek liboqs (Open Quantum Safe) derleme betigi.
# Kaynak kod bu paketin icinde (vendor/liboqs-main.tar.gz) - internet
# baglantisi olmadan (air-gapped) da derlenebilir.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$HERE/liboqs-build"
INSTALL_DIR="$HERE/liboqs-install"

echo "[1/4] liboqs kaynagi aciliyor..."
rm -rf "$HERE/liboqs-src"
mkdir -p "$HERE/liboqs-src"
tar xzf "$HERE/vendor/liboqs-main.tar.gz" -C "$HERE/liboqs-src" --strip-components=1

echo "[2/4] cmake ile yapilandiriliyor (sadece ML-KEM-1024 + ML-DSA-87)..."
rm -rf "$BUILD_DIR"
cmake -S "$HERE/liboqs-src" -B "$BUILD_DIR" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_1024;SIG_ml_dsa_87" \
  -DOQS_BUILD_ONLY_LIB=ON

echo "[3/4] derleniyor..."
cmake --build "$BUILD_DIR" -j"$(nproc)"
cmake --install "$BUILD_DIR"

echo "[4/4] ishv4_pqc_bridge derleniyor..."
gcc -O2 -I"$INSTALL_DIR/include" -o "$HERE/ishv4_pqc_bridge" \
  "$HERE/ishv4_pqc_bridge.c" "$INSTALL_DIR/lib/liboqs.a" -lpthread -lcrypto -lm

echo ""
echo "Tamamlandi: $HERE/ishv4_pqc_bridge"
echo "Test icin:  $HERE/ishv4_pqc_bridge kem-keygen"
