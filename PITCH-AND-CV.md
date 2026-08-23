# CV / Portfolyo / Yatırımcı Sunumu — Dürüst Versiyon

## CV / Portfolyo İçin (bireysel proje olarak)

**Önerilen başlık:**
"Gerçek Post-Kuantum Kriptografi ve HA Konsensüs Destekli KMS Motoru"
(İngilizce: "Production-Pattern KMS Engine with Real PQC, HSM, and Raft
Consensus")

**Önerilen özet (1 paragraf):**
> Sıfırdan, gerçek kriptografik ilkellerle (AES-256-GCM, Shamir's Secret
> Sharing, liboqs ML-KEM-1024/ML-DSA-87) inşa edilmiş bir Key Management
> System. Gerçek PKCS#11 HSM entegrasyonu, Vault durumunu gerçekten
> çoğaltan Raft konsensüs kümesi (HMAC mesaj imzalama ile), RFC 6238
> uyumlu MFA, ve kapsamlı güvenlik test paketi (dudect tarzı zamanlama
> analizi, red-team saldırı simülasyonu, gerçek yük testi) içerir. Her
> iddia gerçek testle doğrulanmış ve README'de belgelenmiştir.

**Neden bu güçlü bir portfolyo parçası:**
- Kriptografi, dağıtık sistemler, güvenlik mühendisliği ve backend
  mimarisinin kesişimini gösteriyor
- "Çalışıyor" demek yerine test kanıtı sunma alışkanlığı (mülakatlarda
  çok değerli — "nasıl test ettin?" sorusuna somut cevap)
- Bulunan ve düzeltilen gerçek hatalar (audit HMAC açığı, HSM doğrulama
  hatası, örnek sayısı raporlama hatası vb.) — bu bir zayıflık değil,
  gerçek mühendislik sürecinin kanıtı

**Mülakatta sorulabilecek sorulara hazırlıklı olun:**
- "Neden Shamir's Secret Sharing?" → K-of-N eşik şeması, tek kişiye
  güven gerektirmez
- "PQC neden önemli?" → Harvest-now-decrypt-later tehdidi, NIST FIPS
  203/204 standardizasyonu
- "Raft'ı nasıl test ettin?" → 3-node kümesi, lider öldürme, yeniden
  seçim, sıfır veri kaybı — gerçek deneyim anlatabilirsiniz

## Yatırımcı Sunumu İçin — DÜRÜST Uyarı

Eğer bunu bir yatırımcıya "hazır ürün" olarak sunarsanız, ilk teknik
inceleme (technical due diligence) şunları soracaktır ve dürüst
cevaplarınız hazır olmalı:

| Soru | Dürüst Cevap |
|---|---|
| "Bağımsız denetimden geçti mi?" | Hayır, henüz değil |
| "Üretimde kaç müşteri var?" | Sıfır — bu bir prototip/motor |
| "FIPS/CC sertifikası var mı?" | Hayır, süreç başlatılmadı |
| "Kaç node'da test ettiniz?" | 3 node, tek fiziksel makinede |
| "SLA/destek var mı?" | Hayır |

**Doğru yatırımcı çerçevesi:** Bunu "hazır ürün" değil, **"gerçek,
test edilmiş bir teknik temel + net bir yol haritası"** olarak sunun.
Yatırımcılar genelde erken aşamada dürüstlüğü ve teknik derinliği,
abartılı hazır-ürün iddialarından daha çok değerlendirir — özellikle
teknik arka planı olan yatırımcılar.

**Önerilen sunum akışı:**
1. Problem: Kuantum tehdidi + KMS pazarındaki güven/şeffaflık eksikliği
2. Çözüm: Gerçek PQC/HSM/HA + tam test şeffaflığı
3. Kanıt: Canlı demo (red-team simülasyonunu izlerken izleyiciye
   gösterin — "işte gerçek zamanda saldırı deniyoruz, işte savunuluyor")
4. Yol haritası: Bağımsız denetim → sertifikasyon → ilk pilot müşteri
5. Sormayın: "Bu HashiCorp Vault'u geçer mi?" — geçmez, ve bunu
   söylemek güven inşa eder, iddia etmemek güveni yıkar

## Ortak Hata: Abartıyla Güven Kaybetmek

Bu projenin geçmişinde (bu konuşmanın başında) tam olarak bu hata
yapılmıştı — sahte sertifikalar, "dünya lideri" iddiaları, çalışmayan
kod. Bu düzeltildi ve şeffaflığa geçildi. **CV'de veya yatırımcı
sunumunda bu şeffaflığı bir hikaye olarak anlatmak** ("başta abartılı
iddialarla başladık, sonra her şeyi gerçek testle doğrulamaya geçtik")
aslında güçlü bir olgunluk göstergesi olabilir — saklamayın.
