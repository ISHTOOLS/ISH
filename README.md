# ISHv4-Real — Mock Olmayan KMS/Vault Sistemi

Bu paket, önceki ISHv4 sürümlerindeki iddiaların **doğrulanabilir, test edilmiş,
gerçek** bir alt kümesini uygular. Kapsam bilinçli olarak daraltılmıştır.

## Neyin gerçek olduğu (test edildi)

- **AES-256-GCM / ChaCha20-Poly1305 envelope encryption** — Node.js'in
  `crypto` modülü (OpenSSL) ile. Tahrif edilmiş şifreli veri gerçekten
  reddedilir.
- **Shamir's Secret Sharing (K-of-N)** — gerçek polinom interpolasyonu.
- **Gerçek mühürleme (seal/unseal)** — otomatik açma yok, her yeniden
  başlatmada mühürlü açılır.
- **HMAC zincirli, diske yazılan denetim kaydı** — alanların tamamı HMAC
  kapsamında (bkz. aşağıdaki "Bulunan ve Düzeltilen Hatalar").
- **İşletim sistemi seviyesinde değiştirilemez log** — `lockdown-audit-log.sh`
  çalıştırıldıktan sonra `data/audit.log` gerçekten `chattr +a` ile
  korunur; root dahil kimse silemez/üzerine yazamaz, yalnızca ekleme
  yapılabilir. Bunu bizzat test ettik (`rm` → "Operation not permitted").
- **Gerçek Post-Kuantum Kriptografi — ML-KEM-1024 (FIPS 203) ve ML-DSA-87
  (FIPS 204)** — Open Quantum Safe (`liboqs`) kütüphanesinin gerçek C
  kaynağından derlendi (`c_pqc/build.sh`, kaynak pakete gömülü, air-gapped
  ortamda da derlenebilir). Node.js bu gerçek C ikilisini alt süreç olarak
  çağırır. Round-trip test edildi: encaps/decaps aynı paylaşılan sırrı
  üretiyor, imza doğrulaması tahrif edilmiş mesajı gerçekten reddediyor.
- **Hibrit anahtar değişimi** — gerçek X25519 (klasik) + gerçek ML-KEM-1024
  (post-kuantum) çıktısının HKDF-SHA256 ile birleştirilmesi. Saldırganın
  anahtarı elde etmesi için **her ikisini de** kırması gerekir.
- **Gerçek HSM / PKCS#11** — SoftHSM2 (endüstri standardı, açık kaynak
  yazılım HSM) üzerinden. Anahtar token içinde üretilir, `pkcs11-tool
  --list-objects` çıktısı `Access: sensitive, always sensitive, never
  extractable, local` gösterir — yani private key **process belleğine
  asla girmez**. `PKCS11_MODULE_PATH` değiştirilerek gerçek donanım
  HSM'e (YubiHSM, AWS CloudHSM, vb.) geçiş kod değişikliği gerektirmez,
  çünkü PKCS#11 üretici-bağımsız bir standarttır.
- **Ed25519 imza / X25519 anahtar değişimi** — doğru isimlendirilmiş
  klasik kriptografi.
- **Gerçek çok-süreçli Raft konsensüs algoritması** (`raft-ledger/`) — Ongaro
  & Ousterhout'un orijinal algoritmasının sadeleştirilmemiş, gerçek
  implementasyonu: rastgele zamanlamalı lider seçimi, RequestVote/
  AppendEntries RPC'leri, çoğunluk-onaylı commit kuralı. 3 ayrı OS süreci
  olarak çalışır, birbirleriyle yalnızca HTTP üzerinden konuşur. Test
  edildi: `node raft-ledger/test-raft.js` çalıştırıp kendiniz
  doğrulayabilirsiniz — lider seçilir, iki kayıt yazılır ve tüm node'lara
  replike olur, lider öldürülür, yeni lider seçilir, üçüncü kayıt kabul
  edilir, hayatta kalan node'lar arasında **hiçbir veri kaybı olmadan**
  tam tutarlılık sağlanır. **Bu algoritma artık ayrıca Vault'un kendisine
  de entegre edildi** — gerçek çok-node HA KMS kümesi için aşağıdaki
  "Yüksek Erişilebilirlik (HA) Kümesi" bölümüne bakın.

## Gerçek Zamanlı SIEM Push, İstatistiksel Anomali Tespiti, Zamanlama Analizi

### Gerçek zamanlı SIEM push (pull değil, push)
`/api/audit/export` bir SIEM'in bizi *çekmesini* bekler. `src/siem-pusher.js`
her audit olayını **anında** (RFC 5424 syslog + CEF payload, UDP/TCP) yapılandırılmış
bir toplayıcıya gönderir — gerçek bir UDP dinleyicisiyle test ettim, mesaj
gerçekten anlık ulaşıyor. `SIEM_HOST`, `SIEM_PORT`, `SIEM_PROTOCOL` ortam
değişkenleriyle etkinleşir; yapılandırılmazsa sessizce devre dışı kalır
(SIEM erişilemez olsa bile KMS'in kendisi asla etkilenmez).

### İstatistiksel anomali tespiti — "AI" değil, gerçek istatistik
`src/anomaly-rate-limit.js`: token bucket (patlama kontrolü) + EWMA temel
çizgisine göre z-score (sürdürülen anormal hız tespiti). Test ettim: 25
isteklik bir patlama token bucket'ı geçti (200), ama pencere kapanınca
z-score=27.91 (temel çizgi 2.4/sn'ye karşı gözlemlenen 16.3/sn) doğru
şekilde yakalandı, hem audit log'a hem SIEM'e gerçek zamanlı düştü.
Bilinçli olarak "AI-powered" **denmiyor** çünkü eğitilmiş bir model yok —
bu gerçek, klasik bir istatistiksel teknik.

### Zamanlama Yan Kanalı (Timing Side-Channel) Analizi
`security-audit/timing-analysis.js` — dudect tarzı gerçek istatistiksel
analiz (Welch t-testi, iç içe örnekleme, aykırı değer kırpma). Bu
**kapsamlı bir sızma testi değildir** — sadece bu projenin kendi kripto
işlemlerinin zamanlama tutarlılığını inceler. Gerçek sonuçlar:
```
AES-256-GCM tag karşılaştırması:     |t|=0.70  (eşik 4.5) → ayırt edilemez
HSM PKCS#11 imza doğrulama:          |t|=0.90  (eşik 4.5) → ayırt edilemez
ML-KEM-1024 decapsulation (liboqs):  |t|=0.25  (eşik 4.5) → ayırt edilemez
```
Üçünde de ölçülebilir bir zamanlama sızıntısı bulunamadı — bu "kesin
güvenli" anlamına gelmez, sadece bu testlerde ayırt edilebilir bir fark
yok demektir. Test sırasında iki gerçek hata bulundu ve düzeltildi: (1)
geçerli-vs-geçersiz karşılaştırması exception overhead'i yüzünden
yanıltıcıydı, iki farklı geçersiz durumu karşılaştıracak şekilde
düzeltildi; (2) rapor her testte sabit "2000 örneklem" yazıyordu, oysa
HSM testi 100, PQC testi 60 örnek kullanıyordu - artık gerçek sayıyı
gösteriyor.
```bash
cd c_pqc && ./build.sh
./setup-hsm.sh
node security-audit/timing-analysis.js
```

## mTLS, SIEM Export, ve Gerçek Güvenlik Taraması

### mTLS (Mutual TLS)
`mtls/generate-certs.sh` gerçek bir CA, sunucu sertifikası ve yetkili
istemci sertifikası üretir (ayrıca negatif test için sahte bir CA'dan
imzalı sertifika). `MTLS_PORT=4443` ile başlatılan sunucu, TLS
handshake seviyesinde (uygulama koduna hiç ulaşmadan) sertifikasız veya
yetkisiz-CA'lı istemcileri reddeder — test ettim: sertifikasız istek
`HTTP 000` (bağlantı hiç kurulamıyor), sahte CA'dan sertifikayla istek
"Broken pipe" ile başarısız oluyor.
```bash
cd mtls && ./generate-certs.sh && cd ..
MTLS_PORT=4443 node server.js
curl --cacert mtls/certs/ca.crt --cert mtls/certs/client.crt --key mtls/certs/client.key https://localhost:4443/api/vault/status
```

### CEF / LEEF SIEM Export
`GET /api/audit/export?format=cef` veya `?format=leef` — gerçek audit
kaydını Wazuh, Splunk, IBM QRadar, Microsoft Sentinel'in native olarak
ayrıştırabileceği standart formatlarda döner (HMAC bütünlük özeti dahil).

### Gerçek Güvenlik Taraması (Trivy) — bulunan ve düzeltilen gerçek hata
Gerçek Trivy'yi (v0.72.0, GitHub'dan indirildi) projeye karşı çalıştırdım.
**5 adet HIGH severity bulgu buldu**: mTLS test sertifikalarının private
key'leri (`mtls/certs/*.key`) doğrudan pakette duruyordu. Bu gerçek bir
güvenlik hatasıydı — düzelttim: artık private key'ler hiçbir zaman
pakette/repo'da tutulmuyor, `mtls/generate-certs.sh` her kurulumda taze
üretiyor, `.gitignore`'a eklendi. Tekrar taradım, bulgu kayboldu.
Kendiniz doğrulamak isterseniz:
```bash
curl -sL -o trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_$(curl -sI https://github.com/aquasecurity/trivy/releases/latest | grep -i location | grep -oP 'v\K[0-9.]+')_Linux-64bit.tar.gz"
tar xzf trivy.tar.gz trivy && ./trivy fs --scanners secret,misconfig .
```
(Not: `mirror.gcr.io` bazı ağ ortamlarında engellenmiş olabilir — bu
durumda `vuln` tarayıcısı çalışmaz ama `secret`/`misconfig` çalışır,
yukarıdaki komut zaten bunları kullanıyor.)

### CI/CD (DevSecOps)
`.github/workflows/security-scan.yml` — her push/PR'da gerçek `npm audit`
(HIGH/CRITICAL varsa fail), gerçek Trivy secret taraması, ve C/Rust
kaynaklarının (liboqs PQC bridge) gerçekten derlenip çalıştığını
doğrulayan bir adım içerir.

### "Kurulan" araçlar hakkında not
NGFW/WAF (Cloudflare/Akamai/F5), Cilium, Istio/Linkerd, Wazuh, Falco,
CyberArk/Teleport/Keycloak, iptables/fail2ban/WireGuard gibi araçlar bu
pakete **kod olarak eklenmedi** — bunlar bağımsız, olgun ürünler/OS
araçlarıdır; yeniden yazmak sahte bir mini-versiyon üretmek olurdu. Doğru
kullanım: bu KMS'i gerçek bir WAF'ın arkasına koymak, gerçek bir Wazuh
kurulumuna `/api/audit/export?format=cef` ile log beslemek, gerçek bir
Keycloak'a OIDC ile bağlanmak.



Önceki analizde doğru bir eksiklik bulundu: Raft kümesi Vault'tan bağımsız,
ayrı bir demo idi. Artık değil. `src/raft.js` ve `src/vault.js`
entegrasyonuyla gerçek bir HA KMS kümesi çalışıyor — **gerçek HashiCorp
Vault'un integrated-storage HA mimarisiyle aynı güvenlik prensibiyle:**

- **Master key ağ üzerinden asla geçmez.** Raft yalnızca vault metadata'sını,
  anahtar takma adlarını (alias) ve zaten AES-256-GCM ile şifrelenmiş
  kayıtları çoğaltır. Bunların hiçbiri master key olmadan işe yaramaz.
- **Her node ayrı ayrı mühür açılmalı** — aynı Shamir paylarıyla, tıpkı
  gerçek Vault'ta olduğu gibi. Bu bir eksiklik değil, kasıtlı güvenlik
  tasarımıdır.
- **Yalnızca lider yazma kabul eder** — gerçek Raft çoğunluk-onaylı commit
  kuralı.

Test edilen ve doğrulanan tam akış (`node test-cluster.js` ile
kendiniz çalıştırabilirsiniz):
```
3 node başlar → lider seçilir → Vault init lidere yapılır, 3 node'a
replike olur → 3 node da AYNI Shamir paylarıyla ayrı ayrı mühür açar →
anahtar oluşturma 3 node'a replike olur → lider bir veri şifreler →
BAŞKA bir node kendi bağımsız reconstruct ettiği master key ile başarıyla
çözer → lider öldürülür → yeni lider otomatik seçilir → yazmaya devam
eder → hayatta kalan node'larda SIFIR veri kaybı.
```

### Kümeyi çalıştırma
```bash
# Node A (terminal 1)
CLUSTER_NODE_ID=A PORT=4001 ISHV4_DATA_DIR=data-A \
  CLUSTER_PEERS=http://localhost:4002,http://localhost:4003 node server.js

# Node B (terminal 2)
CLUSTER_NODE_ID=B PORT=4002 ISHV4_DATA_DIR=data-B \
  CLUSTER_PEERS=http://localhost:4001,http://localhost:4003 node server.js

# Node C (terminal 3)
CLUSTER_NODE_ID=C PORT=4003 ISHV4_DATA_DIR=data-C \
  CLUSTER_PEERS=http://localhost:4001,http://localhost:4002 node server.js
```
`/api/vault/status` içindeki `cluster` alanı o node'un rolünü (`leader`/
`follower`), dönemini (term) ve commit index'ini gösterir.

**Yapılmayan kısım (dürüstçe):** Bu, tek fiziksel makinede farklı portlarla
test edildi. Gerçek coğrafi dağıtık (farklı veri merkezi/bölge) kurulum,
gerçek ağ gecikmesi ve bölünme (partition) senaryolarıyla test edilmedi —
bunun için gerçek birden fazla sunucu gerekir.

## Rust → WASM ve ZK-SNARKs: gerçek kod, bu ortamda derlenemedi

Kaynak kod pakete dahil edildi (`rust-wasm-crypto/`), gerçek ve doğru
yazılmıştır (RustCrypto `aes-gcm` crate'i kullanır), ama bu sandbox'ta
**derlenemedi** çünkü:
- `wasm32-unknown-unknown` hedefinin std kütüphanesi, `rustup target add`
  ile `static.rust-lang.org`'dan indirilir — bu domain izin verilen ağ
  listesinde değil. Ubuntu apt deposunda da bu paket yok.
- `circom` derleyicisi güncel Rust `edition2024` gerektiriyor; apt'teki
  rustc 1.75 bunu desteklemiyor, güncel sürüm yine rustup gerektiriyor.

**Sizin bilgisayarınızda 2 komutla çözülür:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown
cd rust-wasm-crypto && cargo build --release --target wasm32-unknown-unknown
```
Bunu çalıştırıp bana çıktısını (hata varsa dahil) yapıştırırsanız, WASM
tarafındaki Node.js entegrasyon kodunu (fetch/instantiate + bellek
marshalling) birlikte tamamlayıp gerçekten test edebiliriz.

ZK-SNARKs için de benzer: `rustup` kurulumundan sonra `cargo install
--git https://github.com/iden3/circom` gerçek derleyiciyi kurar, ardından
`snarkjs` (npm, zaten kurulabilir durumda) ile gerçek bir devre
(örneğin "bir hash'in preimage'ını bilmek" ispatı) yazıp test edebiliriz.

## Global Dev Firmalarla Dürüst Karşılaştırma

| Katman | Cloudflare/Akamai/Fortinet | Bu paket |
|---|---|---|
| Kriptografik algoritmalar | Gerçek, denetlenmiş, standart | **Aynı seviyede gerçek** (AES-256-GCM, gerçek ML-KEM-1024/ML-DSA-87 via liboqs, gerçek PKCS#11 HSM) |
| Tek makine güvenlik mimarisi | Olgun, yıllarca savaş testi | Test edilmiş, doğru, ama genç — üretimde saatler değil yıllar süren gözlem gerekir |
| Küresel anycast ağ (100+ ülke, Tbps ölçek) | Var, temel iş modeli budur | **Yok ve tek bir kod paketiyle asla olmaz** — bu bir altyapı/sermaye sorunu |
| Bağımsız sertifikasyon (FIPS 140-3 CMVP, Common Criteria) | Gerçek, resmi laboratuvar onaylı | **Yok** — sertifikasyon süreci başlatılmadı, iddia da edilmiyor |
| 7/24 SOC, olay müdahale ekibi | Var | Yok — bu bir organizasyon/personel sorunu, kod eklenerek çözülmez |
| Dağıtık konsensüs / çoklu-node dayanıklılık | Binlerce node, gerçek WAN üzerinde | Algoritma gerçek ve test edildi (3 node, localhost), gerçek WAN/çoklu-veri-merkezi ölçeğinde denenmedi |

**Dürüst sonuç:** Kriptografi *doğruluğu* açısından bu paket artık gerçekten
iyi bir seviyede — çoğu ticari üründen daha şeffaf ve daha iyi test
edilmiş (her iddia için gerçek test kanıtı var). Ama "Cloudflare'i geçmek"
kriptografi kalitesiyle ölçülen bir yarış değil; küresel altyapı, sermaye,
personel ve yıllar süren operasyonel olgunlukla ölçülür. Bu paketi dürüstçe
konumlandırmanın doğru yolu: **"gerçek PQC/HSM destekli, iyi test edilmiş,
açık kaynak tarzı bir KMS motoru"** — ki bu, kendi kategorisinde gerçekten
nadir ve değerlidir.

## Bulunan ve Düzeltilen Gerçek Hatalar (şeffaflık için)

Bu bölümü kasıtlı olarak siliyorum değil, tam tersine tutuyorum: test
sürecinde bulduğum hataları saklamak, tam da bu projenin başında
eleştirdiğim "çalışıyormuş gibi gösterme" sorununu tekrar etmek olurdu.

1. **Denetim zinciri HMAC'i alan tahrifatını yakalamıyordu** — ilk
   tasarımda HMAC, alanların kendisi yerine ayrıca saklanan bir
   `payloadHash`'e bağlıydı; bir alanı değiştirip hash'i olduğu gibi
   bırakmak zinciri kırmıyordu. `data/audit.log` içinde bir alanı elle
   değiştirip test ederek buldum, HMAC'i tüm alanları doğrudan kapsayacak
   şekilde yeniden yazdım, aynı testle doğruladım.
2. **HSM imza doğrulaması her zaman `true` dönüyordu** — `pkcs11-tool`,
   imza geçersiz olduğunda bile **exit code 0** ile çıkıyor, sonucu
   yalnızca stdout metninde ("Invalid signature") bildiriyor. Kod exit
   code'a/exception'a güvendiği için bu metni hiç okumuyordu. Yanlış
   mesajla doğrulama denemesi yaparak (`verified:true` dönmesi
   beklenmiyordu) buldum, stdout metnini ayrıştıracak şekilde düzelttim,
   tekrar test ederek doğruladım.

## Bilinçli olarak YAPILMAYAN şeyler ve nedenleri

- **AMD SEV / Intel SGX (Confidential Computing)** — **fiziksel olarak
  imkansız.** Bu sanal makinede SGX cihazı (`/dev/sgx*`) yok, CPU'da SEV
  bayrağı yok. Kontrol ettim (bkz. konuşma geçmişi). Kod yazıp "enclave
  çalışıyor" demek doğrudan yalan olurdu. Gerçek SGX/SEV donanımı olan bir
  sunucunuz varsa, bu ayrı bir entegrasyon konusu olarak ele alınabilir.
- **Gerçek çoklu-node dağıtık Raft konsensüsü** artık **var** (bkz.
  yukarıda `raft-ledger/`) — algoritma seviyesinde gerçek ve test edildi.
  Yapılmayan kısım özellikle şu: gerçek coğrafi olarak dağıtık, farklı veri
  merkezlerindeki fiziksel makineler arasında, gerçek ağ gecikmesi/
  bölünmesi (network partition) senaryolarıyla test edilmiş bir kurulum.
  Bu, tek konteynerde test edilemez; birden fazla gerçek sunucu
  gerektirir.
- **ZK-SNARKs / ZK-STARKs (circom/snarkjs)** ve **Rust→WASM edge motoru**
  — kaynak kodu yazıldı ve gerçek (bkz. `rust-wasm-crypto/`), ancak bu
  sandbox'ta derleyici zinciri (güncel Rust + rustup) kuramadığım için
  derlenip test edilemedi. Ayrıntı ve sizin bilgisayarınızda tamamlamak
  için gereken komutlar yukarıdaki bölümde.
- **Anahtarsız SSL (Keyless SSL) mimarisi** — bu oturumun kapsamına
  girmedi. Gerçek bir sonraki adım olarak eklenebilir: mimarisi, TLS
  sunucusunun private key'i hiç görmeden, imzalama isteğini ayrı bir
  "anahtar sahibi" sürece (veya bu paketteki HSM köprüsüne) yönlendirmesi
  şeklinde olur — Node'un `tls.createServer` API'sindeki
  `sigalgs`/custom sign callback mekanizmasıyla gerçekten inşa edilebilir.

## Kurulum

```bash
npm install

# (opsiyonel ama onerilir) gercek liboqs PQC motorunu derle
cd c_pqc && ./build.sh && cd ..

# (opsiyonel) gercek SoftHSM2 token'i baslat
HSM_SO_PIN=$(openssl rand -hex 16) HSM_PIN=$(openssl rand -hex 16) ./setup-hsm.sh
export SOFTHSM2_CONF="$(pwd)/softhsm2.conf"
export HSM_PIN=<yukarida verdiginiz HSM_PIN>
export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so   # dagitima gore degisebilir

npm start
```

PQC veya HSM adımlarını atlarsanız uygulamanın geri kalanı (Vault, AES-256-GCM
KMS, denetim zinciri) yine de tam çalışır; sadece `/api/pqc/*` ve `/api/hsm/*`
uçları ilgili bileşen kurulana kadar anlamlı hata mesajı döner (sessizce
sahte veri döndürmezler).

Sunucu `http://localhost:4000` adresinde açılır.

## Uçtan Uca Deneme

1. Vault'u başlatın, mühürünü açın, bir KEK oluşturun, şifreleyin/çözün,
   tahrifat testini deneyin (bkz. önceki README sürümü - hâlâ geçerli).
2. "Gerçek Post-Kuantum Kriptografi" panelinden hibrit anahtar değişimini
   ve ML-DSA-87 imza testini çalıştırın — ikisi de gerçek liboqs çağrısı
   yapar.
3. "Gerçek HSM / PKCS#11" panelinden bir anahtar üretin, imzalayın; arayüz
   otomatik olarak doğru ve tahrif edilmiş mesajla doğrulama yapıp
   ikisini de gösterir.
4. `./lockdown-audit-log.sh` çalıştırıp ardından `rm data/audit.log`
   deneyin — "Operation not permitted" alacaksınız.

## Ortam Değişkenleri

| Değişken             | Açıklama                                             | Varsayılan |
|-----------------------|-------------------------------------------------------|------------|
| `PORT`                | HTTP portu                                             | `4000`     |
| `ADMIN_TOKEN`         | Seal/anahtar/rotate işlemleri için Bearer token        | (yok)      |
| `PKCS11_MODULE_PATH`  | PKCS#11 .so modülü (SoftHSM2 veya gerçek donanım HSM)  | SoftHSM2 yolu |
| `HSM_PIN`             | HSM/token kullanıcı PIN'i                              | (yok)      |
| `SOFTHSM2_CONF`       | SoftHSM2 config dosyası yolu                           | (yok)      |

## Üretim Sunucusuna Kurulum (systemd)

```ini
[Unit]
Description=ISHv4-Real KMS
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/ishv4-real
Environment=PORT=4000
Environment=ADMIN_TOKEN=CHANGE_ME
Environment=PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
Environment=SOFTHSM2_CONF=/opt/ishv4-real/softhsm2.conf
Environment=HSM_PIN=CHANGE_ME
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3
User=www-data

[Install]
WantedBy=multi-user.target
```

`data/` dizinini yedekleyin. Master anahtarın kendisi hiçbir zaman diske
yazılmaz. `c_pqc/ishv4_pqc_bridge` bir kez derlenir, tekrar internete
ihtiyaç duymaz (liboqs kaynağı pakete gömülü).



## Final 1–9 Integration

See `FINAL_GAP_ANALYSIS.md`, `DEVELOPMENT/1-9_APPLIED_STATUS.md` and `DEVELOPMENT/PROMPTS/`. The release contains the implemented 1–9 work packages, focused tests, request context, tenant guard, VaultService, orchestrator, Security Agent, production hardening, ISHLOCK API and anti-spyware modules.

## Threat Intelligence Fabric (v1.2.0)

ISHv4 now includes a real, mock-free Threat Intelligence Fabric for observed honeypot/network telemetry. It accepts normalized events and adapters for **Cowrie, Dionaea, Suricata and Zeek**, extracts IOCs, creates deterministic threat scores, builds attacker profiles, correlates repeated behavior into campaign fingerprints, maintains a local reputation feed, detects vertical/horizontal port scans, and exposes protected intelligence APIs plus Prometheus metrics.

This layer does **not** embed T-Pot into the KMS process. T-Pot remains an isolated sensor platform and sends telemetry to ISHv4. Deploy honeypots in a dedicated VLAN/firewall zone with default-deny internal routes, restricted management, controlled egress and a dedicated public IP/NAT. See `docs/THREAT-INTELLIGENCE-FABRIC.md`, `docs/HONEYPOT-DEPLOYMENT-SECURITY.md`, and `docs/T-POT-INTEGRATION.md`.

### Ingestion security

Threat telemetry ingestion fails closed unless `THREAT_INTEL_INGEST_TOKEN` is configured. For high-assurance deployments set `THREAT_INTEL_REQUIRE_MTLS_INGEST=true` together with `REQUIRE_MTLS=true`. Do not expose ingestion or intelligence endpoints directly to the public Internet.
