# Güvenlik Politikası

## Desteklenen Sürümler
Bu proje aktif geliştirme aşamasındadır. Yalnızca `main` dalındaki en güncel
sürüm güvenlik güncellemeleri alır.

## Bir Güvenlik Açığı Bulduysanız

**Lütfen GitHub Issues üzerinden herkese açık bildirim YAPMAYIN.** Bir
güvenlik açığı bulursanız:

1. Detayları özel olarak bildirin (proje sahibinin e-posta adresine).
2. Şunları ekleyin: etkilenen bileşen (Vault/PQC bridge/HSM bridge/Raft/
   diğer), yeniden üretme adımları, potansiyel etki, varsa önerilen düzeltme.
3. 72 saat içinde bir onay yanıtı almayı bekleyebilirsiniz.
4. Düzeltme yayınlanana kadar detayları herkese açık paylaşmamanızı rica
   ederiz (sorumlu ifşa / responsible disclosure).

## Kapsam
Bu politika şunları kapsar:
- `src/` altındaki tüm kriptografik ve iş mantığı kodu
- `c_pqc/` içindeki PQC köprüsü
- `src/hsm-bridge.js` ve PKCS#11 entegrasyonu
- `src/raft.js` ve küme protokolü

Kapsam DIŞI: üçüncü taraf bağımlılıklar (bunlar için ilgili projenin
kendi güvenlik politikasına başvurun — liboqs, OpenSSL, Node.js, npm
paketleri), SoftHSM2'nin kendisi (Open Quantum Safe / OpenSC projelerine
bildirin).

## Otomatik Zafiyet Taraması
Bu depo şunları otomatik çalıştırır (bkz. `.github/workflows/`):
- **Dependabot**: npm, cargo ve GitHub Actions bağımlılıkları için günlük/
  haftalık otomatik güncelleme PR'ları (`.github/dependabot.yml`)
- **npm audit**: her push/PR'da, HIGH/CRITICAL varsa build fail olur
- **Trivy secret taraması**: her push/PR'da, sızdırılmış anahtar/sır
  taraması

## Bilinen Sınırlamalar (şeffaflık için)
Bu proje henüz bağımsız bir üçüncü taraf güvenlik denetiminden veya
penetrasyon testinden geçmedi. Üretim ortamında kritik veri için
kullanmadan önce bağımsız bir denetim yaptırmanızı önemle tavsiye ederiz.
