# Multi-Currency Payments + GitHub License Authority

## Payment model

ISH supports merchant-configured TRY, EUR and USD commercial plans. Each plan has one authoritative amount, currency and duration. A payment order is bound to the plan currency and returns only that currency's configured bank account.

Configure `ISH_PAYMENT_ACCOUNTS_JSON` as a secret/environment value. Example shape (use real values only in deployment configuration):

```json
{
  "TRY": { "bank": "...", "accountName": "...", "iban": "...", "method": "BANK_TRANSFER", "country": "TR" },
  "EUR": { "bank": "...", "accountName": "...", "iban": "...", "bic": "...", "method": "SWIFT", "country": "TR" },
  "USD": { "bank": "...", "accountName": "...", "iban": "...", "bic": "...", "method": "SWIFT", "country": "TR" }
}
```

`ISH_PLANS_JSON` contains the authoritative merchant prices, for example one plan per currency:

```json
[
  { "id": "pro-tr", "name": "ISH Pro", "amount": 12999, "durationDays": 365, "currency": "TRY" },
  { "id": "pro-eu", "name": "ISH Pro", "amount": 299, "durationDays": 365, "currency": "EUR" },
  { "id": "pro-us", "name": "ISH Pro", "amount": 329, "durationDays": 365, "currency": "USD" }
]
```

Do not put real bank credentials or private keys in the public repository.

## GitHub License Authority

The commercial license remains an Ed25519 signed `ISH-L1` token. GitHub Actions is the issuance authority; the signing private key is stored only as the GitHub Actions environment secret `ISH_LICENSE_PRIVATE_KEY` in the protected `license-authority` environment.

Workflow: `.github/workflows/github-license-authority.yml`

1. Admin confirms a payment.
2. Admin manually dispatches the GitHub workflow with customer ID, plan ID, HWID, duration, paid order ID and payment reference.
3. GitHub Actions signs the license using the private Ed25519 key.
4. The workflow publishes a short-retention artifact containing `license.txt`.
5. The customer receives the license token.
6. ISH verifies the token locally with the public key; a license server is not required for normal validation.

The customer executable must contain only the public verification key. Never ship `ISH_LICENSE_PRIVATE_KEY`.

## Revocation

Offline verification means an already-issued license cannot be remotely revoked while the machine is completely offline. An optional future GitHub revocation feed can provide online revocation checks without becoming a mandatory license server.
