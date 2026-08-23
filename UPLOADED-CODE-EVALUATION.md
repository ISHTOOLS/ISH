# Yüklenen Zip / Kod Örnekleri Değerlendirmesi

Bu belge, size gönderilen `ishv4-enhanced.zip` ve iki kod örneğinin
(`ishv5_engine.py`, `server.js`) neden **olduğu gibi entegre edilmediğini**
ve bunun yerine **gerçekte ne yapıldığını** açıklar.

## Neden olduğu gibi entegre edilmedi

Zip'teki `src/core/orchestrator.js`, `src/tenant-manager.js`,
`src/crypto/ishv5.js` gibi dosyalar **iskelet/placeholder kodlardı**
(toplam 88 satır, 7 dosya) — talimatın kendisinin yasakladığı tam da
buydu ("no mock or placeholder logic"). Somut bulgular:

- `src/crypto/ishv5.js`: `crypto.pbkdf2Sync(input, 'ishv5', ...)` —
  **sabit, herkese açık bir salt** kullanıyordu. Bu ciddi bir
  kriptografi hatasıdır (rainbow table direncini tamamen ortadan
  kaldırır).
- `src/tenant-manager.js`: `new Map()` ile sadece bellekte tutuluyordu,
  hiç diske yazılmıyordu — sunucu yeniden başlayınca tüm veri kaybolur.
  Hiçbir izolasyon mantığı yoktu, sadece bir kayıt defteriydi.
- `src/core/orchestrator.js`: `vault.getKey()` gibi gerçek `vault.js`'imde
  **var olmayan** metodları çağırıyordu — gerçek sisteme hiç bağlı
  değildi.

Ayrıca yapıştırılan `server.js` örneğinde gerçek bir tasarım hatası
vardı: `MASTER_KEY` ortam değişkeni yoksa her yeniden başlatmada
rastgele üretiliyordu — yani önceki şifreli veri kalıcı olarak
çözülemez hale gelirdi. Bu, tam olarak bu projede daha önce bulup
düzelttiğimiz "sahte kolaylık, gerçek hata" desenine bir örnekti.

## Gerçekte ne yapıldı

Bu dosyaların **arkasındaki gerçek fikri** (çok-kiracılı izolasyon)
aldım ve sıfırdan, mevcut gerçek `vault.js`'e tam entegre, test edilmiş
şekilde inşa ettim:

- `src/tenant-manager.js` — **gerçekten diske yazılan** tenant kaydı
- `vault.js`'deki her anahtar ve şifreli kayıt artık bir `tenantId`
  taşıyor
- **Kriptografik izolasyon**: aynı alias adı iki farklı tenant'ta
  kullanılsa bile, KEK türetimi `tenantId:alias` üzerinden yapılıyor —
  yani iki tenant'ın "aynı isimli" anahtarları **matematiksel olarak
  farklı anahtarlardır**, sadece mantıksal olarak ayrılmış değil
- **Erişim izolasyonu test edildi**: Sirket A, Sirket B'nin secret
  ID'sini bilse bile (`decryptSecretById`) `403` ile reddediliyor —
  7/7 test senaryosu geçti (bkz. konuşma geçmişi)
- Geriye dönük uyumluluk korundu: `tenantId` belirtilmezse her şey
  `"default"` tenant'ı ile eskisi gibi çalışıyor

## Neden bu daha iyi bir yaklaşım

Bir "entegrasyon talimatı"nı olduğu gibi uygulamak yerine, önce **kodu
gerçekten okudum**, gerçek olmayan/riskli kısımları belirledim, ve
sadece **gerçekten değerli olan fikri** kendi test standartlarımla
yeniden inşa ettim. Bu, bu projenin başından beri takip ettiğimiz
ilkeyle birebir tutarlı: iddiaları değil, test edilmiş kodu esas almak.
