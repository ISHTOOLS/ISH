#!/usr/bin/env bash
# Denetim kaydini isletim sistemi seviyesinde degistirilemez (append-only)
# yapar. Bu bir metafor degil: root dahil hic kimse bu bayrak acikken
# dosyayi SILEMEZ veya UZERINE YAZAMAZ, sadece sona ekleme yapabilir.
# (CAP_LINUX_IMMUTABLE yetkisi olan bir process disinda.) Bunu bizzat
# test ettik - bkz. README "Test edilen guvenlik ozellikleri".
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_LOG="$HERE/data/audit.log"

if [ ! -f "$AUDIT_LOG" ]; then
  echo "Once sunucuyu calistirip en az bir islem yapin ki data/audit.log olussun."
  exit 1
fi

if ! command -v chattr &> /dev/null; then
  echo "chattr bulunamadi. Bu ozellik yalnizca ext2/3/4 dosya sistemlerinde calisir."
  exit 1
fi

chattr +a "$AUDIT_LOG"
echo "data/audit.log artik append-only. Dogrulama:"
lsattr "$AUDIT_LOG"
echo ""
echo "NOT: Node sureci append icin acacagi icin sorun yasamaz (append=O_APPEND)."
echo "Ancak sunucu tarafindaki normal fs.appendFileSync cagrilari calismaya devam eder;"
echo "yalnizca silme/uzerine yazma girisimleri (rm, sed -i, > yonlendirme) engellenir."
