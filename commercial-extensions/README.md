# Commercial Extensions — Çekirdekten Bilinçli Olarak Ayrılmış Modüller

Bu klasördeki her şey **varsayılan olarak kapalıdır** ve `src/` altındaki
çekirdek koddan **hiçbir zaman otomatik olarak çağrılmaz.** Sadece
`/api/admin/modules` üzerinden bir süper admin tarafından açıkça
etkinleştirildiğinde devreye girer (bkz. `src/module-registry.js`).

## Neden ayrı bir klasör?

Bu projenin temel hedefi — devlete/kuruma sunulabilecek, FIPS 140-3/
Common Criteria tarzı bağımsız denetime hazır, **tam olarak okunabilir
ve denetlenebilir** bir KMS — ile aşağıdaki özellikler **yapısal olarak
çelişir:**

- Kod obfuscation
- Kod/modül şifreleme (at-rest)
- HWID tabanlı lisans zorlaması

Bir denetçi obfuscate edilmiş veya şifrelenmiş kodu inceleyemez. Bu
yüzden bu modülleri `src/`'e karıştırmak yerine, tamamen ayrı bir
klasörde, açıkça "sertifikasyon-uyumsuz" etiketiyle tuttuk.

**Sonuç:** Devlete/denetime sunulacak bir dağıtım, bu klasörü hiç
paketlemeyebilir (`rm -rf commercial-extensions/` yeterli) veya
paketlese bile hiçbir modül varsayılan olarak açık olmadığı için
davranış değişmez. Ticari/SaaS bir dağıtım ise, ihtiyaç duyduğu
modülleri admin panelinden bilinçli olarak açar.

## Modüller

| Modül | Durum | Not |
|---|---|---|
| `hwid-licensing.js` | ✅ Yazıldı, test edildi | Gerçek makine parmak izi (hostname+platform+CPU+RAM, SHA-256), gerçek lisans doğrulama, 4 test senaryosu geçti |
| `behavioral-analysis.js` | ✅ Yazıldı, test edildi | **Rıza zorunlu, atlatılamaz.** Rıza olmadan hiçbir veri toplanmaz/analiz edilmez. Rıza geri çekilince veri fiilen silinir. "AI" değil — basit, şeffaf istatistiksel eşik kuralı (bkz. modül içi yorum). 5 test senaryosu geçti. |
| `code-obfuscation` | ⏳ Kayıtta tanımlı, henüz implementasyon yok | Gerçek bir JS obfuscator (örn. `javascript-obfuscator` npm paketi) build pipeline'ına entegre edilebilir — isterseniz bir sonraki adım |
| `code-encryption-at-rest` | ⏳ Kayıtta tanımlı, henüz implementasyon yok | Modül dosyalarını AES-256 ile şifreleyip runtime'da çözme — isterseniz bir sonraki adım |
| `subscription-billing` | ⏳ Kayıtta tanımlı, henüz implementasyon yok | API key kotaları, kullanım sayacı — isterseniz bir sonraki adım |

## Etik/hukuki not (behavioral-analysis için)

Fare hareketi, yazma temposu gibi davranışsal veriler gerçek kişilere ait
biyometrik-benzeri verilerdir. Bu modül rıza olmadan **hiçbir şekilde**
çalışmayacak şekilde tasarlandı (kod seviyesinde zorunlu, config ile
bypass edilemez). Yine de bunu üretimde kullanmadan önce
`DATA-HANDLING.md`'yi güncelleyip bir hukuk danışmanına göstermenizi
öneririz — KVKK/GDPR'da biyometrik/davranışsal veriler genelde "özel
kategori veri" sayılabilir ve ek yükümlülükler getirebilir.
