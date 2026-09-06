import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-iban-'));
process.env.ISH_PAYMENT_DATA_DIR = temp;
process.env.ISH_PAYMENT_BANK = 'Enpara';
process.env.ISH_PAYMENT_ACCOUNT_NAME = 'ISH Test Account';
process.env.ISH_PAYMENT_IBAN = 'TR000000000000000000000000';
process.env.ISH_PAYMENT_CURRENCY = 'TRY';

const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
process.env.ISH_LICENSE_PRIVATE_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' });
process.env.ISH_LICENSE_PUBLIC_KEY = publicKey.export({ type: 'spki', format: 'pem' });

const payment = await import('../commercial-extensions/iban-payment.js');
const licensing = await import('../commercial-extensions/signed-license.js');

test('creates an IBAN payment order with unique reference', () => {
  const order = payment.createPaymentOrder({
    customerId: 'customer-1',
    customerEmail: 'customer@example.invalid',
    planId: 'pro',
    amount: 499,
    hwid: 'real-hwid-value',
    durationDays: 30
  });

  assert.equal(order.status, 'PENDING');
  assert.match(order.reference, /^ISH-[A-F0-9]{12}$/);
  assert.equal(order.amount, 499);
  assert.equal(order.currency, 'TRY');
  assert.equal(order.hwid, undefined);
  assert.equal(order.payment.iban, process.env.ISH_PAYMENT_IBAN);
  assert.ok(payment.getPaymentOrder(order.id));
});

test('rejects payment confirmation when amount differs', () => {
  const order = payment.createPaymentOrder({
    customerId: 'customer-2',
    planId: 'pro',
    amount: 499,
    hwid: 'real-hwid-2',
    durationDays: 30
  });

  assert.throws(
    () => payment.confirmPayment({ id: order.id, adminId: 'admin-1', receivedAmount: 498 }),
    /does not match/
  );
  assert.equal(payment.getPaymentOrder(order.id).status, 'PENDING');
});

test('paid order produces an HWID-bound signed license', () => {
  const order = payment.createPaymentOrder({
    customerId: 'customer-3',
    planId: 'enterprise',
    amount: 999,
    hwid: 'real-hwid-3',
    durationDays: 365
  });

  payment.confirmPayment({ id: order.id, adminId: 'admin-1', receivedAmount: 999 });
  const internal = payment.getPaymentOrderInternal(order.id);
  const token = licensing.issueSignedLicense({ order: internal });
  const result = licensing.verifySignedLicense(token);

  assert.equal(result.valid, true);
  assert.equal(result.payload.customerId, 'customer-3');
  assert.equal(result.payload.planId, 'enterprise');
  assert.equal(result.payload.hwid, 'real-hwid-3');
  assert.equal(result.payload.orderId, order.id);
});

test('tampered signed license is rejected', () => {
  const order = payment.createPaymentOrder({
    customerId: 'customer-4',
    planId: 'basic',
    amount: 99,
    hwid: 'real-hwid-4',
    durationDays: 30
  });
  payment.confirmPayment({ id: order.id, adminId: 'admin-1', receivedAmount: 99 });
  const token = licensing.issueSignedLicense({ order: payment.getPaymentOrderInternal(order.id) });
  const [prefix, payload, signature] = token.split('.');
  const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  decoded.planId = 'enterprise';
  const tamperedPayload = Buffer.from(JSON.stringify(decoded)).toString('base64url');
  const result = licensing.verifySignedLicense(`${prefix}.${tamperedPayload}.${signature}`);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'Invalid signature');
});
