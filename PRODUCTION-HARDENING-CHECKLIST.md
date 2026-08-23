# Production Hardening Checklist

Bu liste, bu projede **gerçekten var olan** özelliklere dayanır — her
madde ya "yapıldı, şöyle etkinleştirilir" ya da "yapılmadı, şu araç/süreç
gerekir" şeklinde işaretlenmiştir. Genel/şablon bir checklist değildir.

## ✅ Kod seviyesinde hazır (sadece etkinleştirme gerekir)

- [ ] `STRICT_MODE=true` — paylaşılan ADMIN_TOKEN yerine gerçek IAM admin
      session zorunluluğu (test edildi)
- [ ] `REQUIRE_MTLS=true` + `MTLS_PORT` — düz HTTP'den erişimi engelle
      (test edildi, `/healthz` istisna)
- [ ] `DISABLE_FALLBACKS=true` — ADMIN_TOKEN yoksa "açık dev modu" yerine
      fail-closed (test edildi)
- [ ] `TRUST_PROXY=false` (varsayılan) — sadece gerçek bir reverse proxy
      arkasındaysanız `true` yapın (test edildi: spoofing engellendi)
- [ ] `CLUSTER_SECRET` — Raft küme kullanıyorsanız zorunlu, mesaj
      imzalama (test edildi: sahte node 401 ile reddedildi)
- [ ] IP Whitelist (`PUT /api/security/ip-whitelist`, mode=strict) —
      bilinen yönetici IP'leriyle sınırlayın (test edildi, CIDR destekli)
- [ ] Content filter kuralları gözden geçirin (`GET /api/filter/rules`)
- [ ] Argon2id parola hash'leme zaten varsayılan (test edildi, RFC
      geriye dönük uyumlu)
- [ ] Anahtar rotasyon/iptal/süre-sonu API'lerini operasyonel sürece
      dahil edin (test edildi)
- [ ] `./mtls/generate-certs.sh` ile gerçek CA/sertifika üretin — asla
      demo sertifikalarını üretimde kullanmayın
- [ ] `./lockdown-audit-log.sh` — `chattr +a` ile audit log'u OS
      seviyesinde değiştirilemez yapın (test edildi, ext2/3/4 gerekir)
- [ ] `commercial-extensions/` klasörünü **hiç dahil etmeyin** eğer
      denetime/sertifikasyona gidecekseniz (`rm -rf commercial-extensions/`)
- [ ] `security-audit/red-team-simulation.js` ve
      `security-audit/timing-analysis.js`'i CI/CD'ye ekleyin

## ⚠️ Kısmen hazır — operasyonel süreç gerekir

- [ ] **Shamir pay dağıtımı** — `KEY-LIFECYCLE-PROCEDURES.md`'deki
      prosedürü gerçek insanlarla, gerçek fiziksel kasalarla uygulayın
      (kod hazır, insan süreci sizin sorumluluğunuzda)
- [ ] **Yedekleme** — `data/` dizinini düzenli yedekleyin (master key
      içermez, ama Shamir payları OLMADAN yedek işe yaramaz)
- [ ] **SIEM entegrasyonu** — `SIEM_HOST`/`SIEM_PORT` ile gerçek bir
      Wazuh/Splunk/Sentinel'e bağlayın (kod hazır, gerçek SIEM
      kurulumu sizin sorumluluğunuzda)

## ❌ Henüz yapılmadı — bu proje kapsamında eklenmedi

- [ ] **Bağımsız güvenlik denetimi / penetrasyon testi** — hiç
      yapılmadı, dışarıdan bir firma gerekir
- [ ] **FIPS 140-3 / Common Criteria sertifikasyonu** — resmi bir
      laboratuvar süreci (CMVP), başlatılmadı
- [ ] **Gerçek çoklu-fiziksel-makine / WAN testi** — Raft/HA şimdiye
      kadar hep tek makinede portlarla simüle edildi
- [ ] **Docker imajının gerçekten build+run edilmesi** — bu geliştirme
      ortamında Docker daemon yoktu, YAML/env doğrulandı ama tam
      build+run testi yapılmadı
- [ ] **Raft node-arası mTLS** — mesaj imzalama (HMAC) var, ama trafik
      şifreli değil (sadece kimlik doğrulanıyor, gizlilik sağlanmıyor)
- [ ] **Rust→WASM derlemesi** — kaynak hazır, bu ortamda derleyici
      zinciri kurulamadı
- [ ] **Log rotasyonu/arşivleme politikası** — audit log kasıtlı olarak
      silinemez, uzun vadede disk yönetimi planı gerekir

## Dağıtım öncesi son kontrol listesi

1. `npm audit` çalıştırın, HIGH/CRITICAL varsa çözün
2. `security-audit/red-team-simulation.js` çalıştırın, tüm testler
   savunulmalı
3. `security-audit/timing-analysis.js` çalıştırın
4. Gerçek Shamir paylarını gerçek insanlara dağıtın, test edin
5. `STRICT_MODE=true`, `DISABLE_FALLBACKS=true` ile başlatın
6. `commercial-extensions/` klasörünün amaçlanan dağıtımda olup
   olmayacağına karar verin
7. Bağımsız bir güvenlik firmasıyla pentest planlayın
