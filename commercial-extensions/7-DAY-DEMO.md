# ISH 7 Gün Demo

## Akış

1. Kullanıcı `/demo.html` üzerinden e-posta ve kurulum HWID'sini girer.
2. `POST /api/demo/7-day` sunucu tarafında Ed25519 imzalı `ISH-D1` demo tokenı üretir.
3. Token tam 7 gün geçerlidir ve HWID'ye bağlıdır.
4. `POST /api/demo/verify` imza, demo türü, HWID ve süreyi doğrular.
5. Aynı e-posta veya HWID ile ikinci demo verilmez.
6. Demo süresi dolduğunda kullanıcı satın alma akışına yönlendirilir.

## Güvenlik

- Private key yalnızca sunucu ortamında `ISH_LICENSE_PRIVATE_KEY` olarak tutulur.
- Public key `ISH_LICENSE_PUBLIC_KEY` ile doğrulama yapılır.
- Demo kayıt defteri e-posta/HWID değerlerini düz metin yerine SHA-256 parmak izi olarak saklar.
- Gerçek kullanıcı verisi dışında demo müşteri/cihaz verisi üretilmez.
- Demo süresi frontend timer/localStorage ile belirlenmez.
- Banka veya ödeme gerektirmez.

## Yönetim

Admin, `GET /api/admin/demo/issuances` endpointinden demo kayıtlarının (hashlenmiş kimlikler ve zaman bilgileri) özetini görebilir.
