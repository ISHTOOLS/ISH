# Tehdit Modeli (STRIDE Metodolojisi)

Bu belge, ISHv4-Real'in **gerçek bileşenlerine** karşı yapılandırılmış bir
STRIDE analizidir. Genel/şablon bir tehdit modeli değildir — her madde bu
kod tabanındaki spesifik bir dosya/mekanizmaya atıfta bulunur.

## Kapsam
- Vault/KMS çekirdeği (`src/vault.js`, `src/crypto-engine.js`)
- Shamir mühürleme (`src/shamir.js`)
- Raft HA kümesi (`src/raft.js`)
- HSM/PKCS#11 köprüsü (`src/hsm-bridge.js`)
- PQC köprüsü (`src/pqc-bridge.js`, `c_pqc/`)
- IAM/RBAC/MFA (`src/iam.js`, `src/totp.js`)
- Audit zinciri (`src/audit.js`)
- Ağ katmanı (mTLS, rate limiting)

## Kapsam Dışı (bu belgede ele alınmıyor)
Fiziksel güvenlik, tedarik zinciri saldırıları (derleme zincirine sızma),
sosyal mühendislik, SGX/SEV donanım gerektiren senaryolar (donanım yok).

---

## S — Spoofing (Kimlik Sahteciliği)

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| Sahte istemci, gerçek istemci gibi API'ye bağlanır | mTLS (CA imzalı sertifika zorunlu) + IAM şifre/MFA | mTLS opsiyonel (varsayılan kapalı) — üretimde zorunlu kılınmalı |
| Bir node, kümedeki başka bir node'un kimliğine bürünür (Raft) | Raft `nodeId` + `term` doğrulaması | Node'lar arası iletişim şu an düz HTTP — mTLS ile şifrelenmeli (henüz Raft trafiğine mTLS uygulanmadı) |
| X-Forwarded-For sahteciliği ile rate limit atlatma | — | **Bilinen açık**: doğrudan internete açılırsa saldırgan bu header'ı sahteleyip anomali tespitini atlatabilir. Gerçek bir reverse proxy (nginx/Cloudflare) arkasında, yalnızca proxy'den gelen güvenilir header kullanılmalı |

## T — Tampering (Veri Tahrifatı)

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| Şifreli veri diskte değiştirilir | AES-256-GCM auth tag (test edildi: tahrifat reddediliyor) | Yok — kriptografik olarak güçlü |
| Audit log'a müdahale | HMAC zinciri + `chattr +a` (test edildi) | `chattr +a` yalnızca ext2/3/4'te çalışır; farklı dosya sistemlerinde bu koruma yok |
| Raft log'una sahte komut enjekte etme | Yalnızca lider yazma kabul eder, term kontrolü | Kötü niyetli bir node kümeye eklenirse (yetkisiz node ekleme koruması yok) sorun olabilir — üye ekleme/çıkarma için ayrı bir yetkilendirme katmanı yok |

## R — Repudiation (İnkâr)

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| Bir operatör bir işlemi yaptığını inkâr eder | HMAC zincirli, zaman damgalı, actor-ID'li audit log | `actorId` şu an IAM login'e bağlı değil — `recordAudit` çoğu yerde `'operator'` sabit string'i kullanıyor. **Gerçek iyileştirme gerekli**: her audit kaydı gerçek IAM kullanıcı adına bağlanmalı |

## I — Information Disclosure (Bilgi İfşası)

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| Master key RAM dökümünden okunur | Master key yalnızca unsealed node RAM'inde, diske asla yazılmaz | Bir saldırgan sunucuya kök erişim + RAM erişimi sağlarsa yine de risk var — bu HSM'in tam çözdüğü sorun |
| PQC/HSM zamanlama yan kanalı ile anahtar sızıntısı | Test edildi, 3 bileşende de ölçülebilir fark bulunamadı | Kapsamlı değil — yalnızca 3 spesifik işlem test edildi |
| Şifrelenmemiş node-arası Raft trafiği dinlenir | — | **Bilinen açık**: Raft trafiği düz HTTP |

## D — Denial of Service

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| API'ye aşırı istek yağdırma | Token bucket + EWMA z-score anomali tespiti (test edildi) | Tek node seviyesinde koruma — gerçek DDoS'a karşı üst katmanda gerçek CDN/scrubbing gerekir |
| Raft lideri hedef alınıp sürekli öldürülür | Otomatik yeniden seçim (test edildi) | Sürekli lider değişimi performansı düşürebilir |

## E — Elevation of Privilege

| Tehdit | Mevcut Önlem | Kalan Risk |
|---|---|---|
| Operator rolü admin işlemlerini yapmaya çalışır | RBAC (`src/iam.js`) — test edildi | RBAC şu an tüm endpoint'lere sistematik bağlanmadı — `requireAdmin` ile paralel duruyor, tam entegre değil |
| MFA olmadan admin işlemi yapma | MFA etkinse zorunlu (test edildi) | Varsayılan olarak MFA kapalı |

---

## Öncelikli Aksiyon Listesi (bu analizden çıkan)
1. **actorId'yi gerçek IAM kimliğine bağla** (şu an çoğu yerde sabit `'operator'`)
2. **RBAC'ı tüm endpoint'lere sistematik uygula**
3. Raft node-arası trafiğe mTLS uygula
4. X-Forwarded-For güvenilirliği için reverse proxy zorunluluğu
5. Kümeye node ekleme/çıkarma için yetkilendirme katmanı ekle
