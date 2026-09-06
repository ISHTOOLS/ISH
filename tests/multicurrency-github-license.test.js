import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

function withEnv(values, fn) {
  const previous = {};
  for (const [key, value] of Object.entries(values)) { previous[key] = process.env[key]; process.env[key] = value; }
  try { return fn(); } finally { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } }
}

test('multi-currency plans select the correct payment account', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-multi-currency-'));
  const accounts = JSON.stringify({
    TRY: { bank: 'Test Bank', accountName: 'ISH', iban: 'TR000000000000000000000000', method: 'BANK_TRANSFER' },
    EUR: { bank: 'Test Bank', accountName: 'ISH', iban: 'TR111111111111111111111111', bic: 'ENASTRISXXX', method: 'SWIFT' },
    USD: { bank: 'Test Bank', accountName: 'ISH', iban: 'TR222222222222222222222222', bic: 'ENASTRISXXX', method: 'SWIFT' }
  });
  withEnv({
    ISH_PAYMENT_ACCOUNTS_JSON: accounts,
    ISH_PLANS_JSON: JSON.stringify([
      { id: 'pro-tr', name: 'Pro TRY', amount: 12999, durationDays: 365, currency: 'TRY' },
      { id: 'pro-eu', name: 'Pro EUR', amount: 299, durationDays: 365, currency: 'EUR' },
      { id: 'pro-us', name: 'Pro USD', amount: 329, durationDays: 365, currency: 'USD' }
    ]),
    ISH_PAYMENT_DATA_DIR: dataDir
  }, async () => {
    const { createPaymentOrder } = await import(`../commercial-extensions/iban-payment.js?test=${crypto.randomUUID()}`);
    const eur = createPaymentOrder({ customerId: 'c-eur', customerEmail: 'x@example.test', planId: 'pro-eu', hwid: 'HW-EUR' });
    const usd = createPaymentOrder({ customerId: 'c-us', planId: 'pro-us', hwid: 'HW-USD' });
    assert.equal(eur.currency, 'EUR');
    assert.equal(eur.payment.currency, 'EUR');
    assert.equal(eur.payment.method, 'SWIFT');
    assert.equal(usd.currency, 'USD');
    assert.equal(usd.payment.currency, 'USD');
  });
});

test('GitHub authority generator emits an Ed25519 signed license', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-github-license-'));
  const output = path.join(tempDir, 'license.txt');
  withEnv({
    ISH_LICENSE_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    LICENSE_CUSTOMER_ID: 'customer-test',
    LICENSE_PLAN_ID: 'enterprise',
    LICENSE_HWID: 'HW-TEST',
    LICENSE_DURATION_DAYS: '365',
    LICENSE_ORDER_ID: 'order-test',
    LICENSE_PAYMENT_REFERENCE: 'ISH-TESTREF',
    LICENSE_OUTPUT_FILE: output
  }, async () => {
    await import(`../commercial-extensions/github-license-authority.js?test=${crypto.randomUUID()}`);
    const token = fs.readFileSync(output, 'utf8').trim();
    assert.match(token, /^ISH-L1\./);
  });
});
