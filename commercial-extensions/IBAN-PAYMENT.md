# ISH IBAN Payment + License Activation

This extension adds a real-data-only payment workflow for a seller who accepts manual Enpara/IBAN transfers without requiring a corporate banking API.

## Flow

1. Customer selects a plan.
2. ISH creates a payment order with a unique `ISH-XXXXXXXXXXXX` reference.
3. The customer receives the configured bank, account name, IBAN, amount, currency and reference.
4. The customer transfers the exact amount and places the reference in the transfer description.
5. The seller verifies the incoming transfer in the bank application.
6. An authenticated administrator confirms the payment in ISH.
7. ISH creates an Ed25519-signed license bound to the customer's HWID.
8. The client verifies the license signature and expiry.

## Configuration

Set these server-side environment variables. Never commit them to Git:

- `ISH_PAYMENT_BANK`
- `ISH_PAYMENT_ACCOUNT_NAME`
- `ISH_PAYMENT_IBAN`
- `ISH_PAYMENT_CURRENCY` (default `TRY`)
- `ISH_PAYMENT_DATA_DIR` (default `./data`)
- `ISH_LICENSE_PRIVATE_KEY` (PEM, server-side only)
- `ISH_LICENSE_PUBLIC_KEY` (PEM)
- `ISH_LICENSE_ISSUER` (optional, default `ISH`)

The private signing key must never be shipped inside the client application or repository.

## Security boundaries

- No fabricated bank transactions are created.
- No bank credentials are stored by this extension.
- Payment confirmation is an authenticated administrative action because this design does not assume a personal Enpara account exposes a production banking API.
- A mismatched payment amount cannot be confirmed.
- Customer email and HWID are not returned by public order endpoints.
- Licenses are signed with Ed25519 and contain the customer HWID, plan, order ID and expiry.
- Tampered licenses fail signature verification.

## Important deployment note

This is an IBAN/havale payment-order workflow, not a payment institution, virtual POS, or automatic bank-statement connector. Automatic bank reconciliation should only be added if a supported, authorized banking data interface is available for the account. Until then, the bank-side verification remains explicitly manual.
