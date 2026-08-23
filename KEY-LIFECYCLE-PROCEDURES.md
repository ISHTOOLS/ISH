# Anahtar Yaşam Döngüsü Prosedürleri

Bu belge, ISHv4-Real'in **gerçek mimarisine** dayanan operasyonel bir
runbook'tur — genel bir şablon değildir.

## 1. Shamir Paylarının Fiziksel Saklanması

Vault `init` işlemi sırasında N adet Shamir payı üretilir, K tanesi
master key'i yeniden oluşturmaya yeterlidir (bkz. `src/shamir.js`,
`src/vault.js`). Sunucu bu payları **hiçbir zaman** diske yazmaz.

**Önerilen prosedür (5 pay, eşik 3 — gerçek Vault/HSM pratiği):**
1. 5 pay, 5 farklı yetkiliye verilir (örn. CTO, Güvenlik Sorumlusu, 2
   Sistem Yöneticisi, 1 harici Emanetçi/Escrow).
2. Her pay ayrı bir fiziksel kasada veya donanımsal güvenlik anahtarında
   (YubiKey şifreli bölüm) saklanır — **asla aynı yerde iki pay
   saklanmaz**.
3. Hiçbir yetkili kendi payını dijital olarak (e-posta, Slack, not
   uygulaması) saklamaz veya iletmez.
4. Yıllık olarak paylar gerçekten okunabilir mi diye test edilir (fiziksel
   kasa açılıp pay okunur, ama sisteme GİRİLMEZ — sadece varlığı
   doğrulanır).

## 2. Mühür Açma (Unseal) Prosedürü

Gerçek sistemde (bkz. `POST /api/vault/unseal`), her node ayrı ayrı
mühürü açılmalıdır:

1. Sistem yeniden başlatıldığında (bakım, çökme, güncelleme) tüm node'lar
   mühürlü başlar (test edildi — otomatik açılma YOK).
2. En az K yetkili fiziksel olarak (veya güvenli bir kanaldan) toplanır.
3. Her biri kendi payını sırayla `POST /api/vault/unseal` ile girer.
4. K'inci pay girildiğinde node açılır. Bu işlem **her node için ayrı
   ayrı** tekrarlanır (küme modunda).
5. **Hiçbir yetkili payını telefon/ekran paylaşımıyla başkasına
   göstermez.**

## 3. Pay Kaybı Senaryoları

| Senaryo | Sonuç | Aksiyon |
|---|---|---|
| 1-2 pay kayboldu (eşik K=3, toplam N=5) | Sistem hâlâ açılabilir | Kalan yetkililerle yeni bir `re-key` işlemi planlanmalı (mevcut sistemde otomatik re-key API'si yok — manuel: yeni vault init + veri taşıma) |
| K'den fazla pay kayboldu | **Veri kalıcı olarak kurtarılamaz** | Bu, kasıtlı bir güvenlik özelliğidir, hata değil — README'de açıkça belirtilmiştir |
| Bir yetkili işten ayrıldı | O kişinin payı **yakılmalı/imha edilmeli**, kalan yetkililerle yeni pay seti üretilecek şekilde re-key yapılmalı | Mevcut sistemde bu otomatik değil — bir sonraki geliştirme adayı |

## 4. Acil Durum Mührü (Emergency Seal)

Bir güvenlik ihlali şüphesi durumunda:
```bash
curl -X POST https://<node>/api/vault/seal \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```
Bu, master key'i **anında** o node'un RAM'inden siler (test edildi).
Küme modunda **her node için ayrı ayrı** çağrılmalıdır.

## 5. Anahtar Rotasyonu (KEK)

`POST /api/kms/keys/:alias/rotate` (test edildi — yeni versiyon
oluşturuyor, eski şifreli veriler eski versiyon numarasıyla hâlâ
çözülebiliyor çünkü `kekVersion` her kayıtla birlikte saklanıyor).

**Önerilen politika:** 90 günde bir rutin rotasyon, veya bir operatörün
işten ayrılması/şüpheli aktivite durumunda acil rotasyon.

## 6. Anahtar İmhası

**Şu anki sistemde gerçek bir "hard delete" API'si YOKTUR** (kasıtlı —
yanlışlıkla veri kaybını önlemek için). Gerçek imha için:
1. Vault'u mühürleyin (yukarıdaki prosedür).
2. `data/secrets.json`, `data/keys.json` dosyalarını güvenli silme
   (`shred -u` veya disk şifreliyse basit `rm` yeterli) ile silin.
3. Tüm Shamir paylarını fiziksel olarak imha edin (kağıtsa yakın,
   donanım token'saysa fabrika sıfırlaması yapın).
4. Bu işlemi audit log'a **harici olarak** (sistemin kendisi artık
   erişilemez olacağı için) kayıt altına alın.

## 7. Felaket Kurtarma (Disaster Recovery)

- `data/` dizini düzenli yedeklenmelidir (şifreli veri + metadata —
  master key içermez, bu yüzden yedek dosyası tek başına risk taşımaz).
- Yedekten geri yükleme sonrası, sistem yine mühürlü başlar — aynı
  Shamir paylarıyla açılması gerekir.
- **Test edilmemiş varsayım:** Bu belge, DR tatbikatının gerçekten
  yapıldığını iddia etmiyor — bu, bu paketin "eksik" listesindeki bir
  sonraki gerçek adımdır.
