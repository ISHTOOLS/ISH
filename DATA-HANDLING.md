# Veri İşleme Notu (Teknik) — KVKK / GDPR Hazırlığı İçin

> ⚠️ **Bu bir hukuki belge DEĞİLDİR.** Bu sadece sistemin teknik olarak ne
> yaptığının dökümüdür. KVKK/GDPR uyumluluğu için mutlaka bir hukuk
> danışmanına bu belgeyi ve gerçek kullanım senaryonuzu göstermeniz
> gerekir. Ben (Claude) hukuki tavsiye veremem.

## Sistemde Hangi Veri Nerede Duruyor

| Veri | Konum | Şifreleme | Saklama Süresi |
|---|---|---|---|
| Şifrelenmiş kullanıcı verisi (ciphertext) | `data/secrets.json` | AES-256-GCM (uygulama katmanında) | Manuel silinene kadar |
| Anahtar metadata (alias, versiyon) | `data/keys.json` | Yok (hassas veri içermiyor) | Manuel silinene kadar |
| Master key | **Hiçbir yerde diskte değil** | N/A — yalnızca RAM, yalnızca unsealed node'da | Sunucu mühürlenene/kapanana kadar RAM'de |
| Kullanıcı şifreleri | `data/iam-users.json` | PBKDF2-HMAC-SHA256, 210.000 iterasyon, düz metin asla yok | Kullanıcı silinene kadar |
| MFA (TOTP) sırları | `data/iam-users.json` | **Düz metin** (TOTP'nin doğası gereği — sunucu kodu üretebilmek için sırrı bilmek zorunda) | Kullanıcı silinene/MFA kapatılana kadar |
| Denetim kayıtları (audit log) | `data/audit.log` | Şifrelenmemiş ama HMAC ile bütünlüğü korunan | Kalıcı (silinmemeli — uyum gereği) |
| IP adresleri (rate limiting, audit) | Bellekte (rate limit) + `data/audit.log` (audit) | Yok | Rate limit: dakikalar; Audit: kalıcı |

## KVKK/GDPR Açısından Dikkat Edilmesi Gereken Noktalar (teknik gözlem)

1. **IP adresleri kişisel veri sayılabilir** (KVKK m.3, GDPR Art. 4) —
   audit log'da kalıcı olarak saklanıyor. Bir hukuk danışmanı bunun
   "meşru menfaat" (güvenlik denetimi) kapsamında olup olmadığını
   değerlendirmeli.
2. **TOTP sırları düz metin saklanıyor** — bu MFA'nın teknik bir
   gerekliliği (RFC 6238), ama dosya izinleri (`0600`) ve disk şifreleme
   ile ek koruma önerilir.
3. **"Unutulma hakkı" (right to erasure) şu an otomatik değil** —
   `KEY-LIFECYCLE-PROCEDURES.md`'deki manuel imha prosedürü izlenmelidir.
   Otomatik bir "kullanıcı verisini sil" API'si yoktur (bir sonraki
   geliştirme adayı).
4. **Audit log kasıtlı olarak silinemez** (HMAC zinciri + `chattr +a`) —
   bu KVKK'nın "veri minimizasyonu" ilkesiyle gerilim yaratabilir. Hukuki
   değerlendirme gerekir: güvenlik/uyum amaçlı zorunlu saklama süresi
   sonunda log rotasyonu/arşivleme politikası tanımlanmalı.
5. **Veri yerelliği (data residency):** Sistem, verinin fiziksel olarak
   nerede saklandığını sizin sunucu seçiminiz belirler — kod bunu
   zorlamaz. Devlet kurumlarına sunumda "veri yurt içinde tutulur"
   iddiası, gerçek sunucu konumuna bağlıdır, koddan bağımsızdır.

## Öneri
Bu belgeyi bir KVKK/GDPR uzmanına gösterip resmi bir "Kişisel Verileri
Koruma Envanteri" ve "Aydınlatma Metni" hazırlatmanızı öneririz — bu,
teknik bir dosya değil, hukuki bir süreçtir.
