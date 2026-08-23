# SBOM (Software Bill of Materials)

Bu belge, ISHv4-Real'in tüm bağımlılık ekosistemlerini kapsar.
`cyclonedx-npm` yalnızca npm ekosistemini otomatik tarayabildiği için,
C ve Rust bağımlılıkları burada manuel olarak dokümante edilmiştir.

## 1. npm (Node.js) — Otomatik Üretilen, Makine Tarafından Okunabilir

- **Üretim (yalnızca gerçekten sunucuya giden kod):** `sbom-production.json`
  (CycloneDX 1.6 formatı, 67 bileşen — tek gerçek üretim bağımlılığı
  `express` ve onun transitive bağımlılıkları)
- **Tam (geliştirme araçları dahil):** `sbom.json` (115 bileşen — yukarıya
  ek olarak `autocannon` yük test aracı)

Yeniden üretmek için:
```bash
npm install -g @cyclonedx/cyclonedx-npm
cyclonedx-npm --omit dev --output-file sbom-production.json
```

## 2. C Bağımlılıkları (manuel — cyclonedx bunları tarayamaz)

| Bileşen | Sürüm | Kaynak | Amaç |
|---|---|---|---|
| liboqs (Open Quantum Safe) | `main` dalı, 2026-07-28 tarihinde pakete gömüldü | github.com/open-quantum-safe/liboqs | Gerçek ML-KEM-1024 / ML-DSA-87 (NIST FIPS 203/204) |
| OpenSSL | 3.0.13 (30 Jan 2024) | Sistem paketi (`libssl-dev`) | liboqs'un bağlı olduğu kriptografik ilkel işlemler, PQC bridge derlemesi |

**Not:** liboqs "main" dalından alındığı için sabit bir sürüm numarası yerine
tarih belirtilmiştir. Üretim dağıtımı için belirli, etiketlenmiş (tagged)
bir liboqs sürümüne (örn. `0.12.0`) sabitlemeniz önerilir — bu, tekrarlanabilir
derleme (reproducible build) ve zafiyet takibi için daha sağlıklıdır.

## 3. Rust Bağımlılıkları (manuel)

| Bileşen | Sürüm | Kaynak | Amaç |
|---|---|---|---|
| aes-gcm (RustCrypto) | `Cargo.lock`'ta sabitlenmiş | crates.io | WASM AES-256-GCM motoru (bkz. `rust-wasm-crypto/`) |

Tam liste için: `rust-wasm-crypto/Cargo.lock` (gerçek, kilitlenmiş sürüm
numaralarıyla).

## 4. Zafiyet Takibi

- npm bağımlılıkları: `.github/dependabot.yml` ile günlük otomatik tarama
- Cargo bağımlılıkları: `.github/dependabot.yml` ile haftalık otomatik tarama
- C bağımlılıkları (liboqs, OpenSSL): **manuel takip gerekir** —
  Dependabot bunları izleyemez. Önerilen: liboqs'un GitHub "Releases"
  sayfasını ve OpenSSL güvenlik duyurularını (openssl.org/news/secadv)
  düzenli kontrol edin, veya `trivy fs` çalıştırıp `vuln` tarayıcısını
  (mirror.gcr.io erişimi gerekir) etkinleştirin.

## Yeniden Üretim ve Doğrulama
Bu SBOM'lar bu depoya karşı gerçekten üretildi ve doğrulandı (bkz. proje
geçmişi). Kendi ortamınızda yeniden üretip karşılaştırmanızı öneririz —
bir SBOM'un değeri, güncel ve doğrulanabilir olmasındadır.
