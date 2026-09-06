import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-commercial-e2e-'));
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
process.env.ISHV4_NO_LISTEN = 'true';
process.env.ISH_PAYMENT_DATA_DIR = dataDir;
process.env.ISH_PAYMENT_BANK = 'Enpara';
process.env.ISH_PAYMENT_ACCOUNT_NAME = 'ISH Test Seller';
process.env.ISH_PAYMENT_IBAN = 'TR000000000000000000000000';
process.env.ISH_PAYMENT_CURRENCY = 'TRY';
process.env.ISH_PLANS_JSON = JSON.stringify([{ id: 'pro', name: 'Professional', amount: 99, durationDays: 30, currency: 'TRY' }]);
process.env.ADMIN_TOKEN = 'commercial-test-admin-token';
process.env.ISH_LICENSE_PRIVATE_KEY = privateKey.export({ format: 'pem', type: 'pkcs8' });
process.env.ISH_LICENSE_PUBLIC_KEY = publicKey.export({ format: 'pem', type: 'spki' });
process.env.NODE_ENV = 'test';

const { app } = await import('../commercial-bootstrap.mjs');
const server = app.listen(0);
const base = await new Promise((resolve) => server.once('listening', () => resolve(`http://127.0.0.1:${server.address().port}`)));

async function request(pathname, options = {}) {
  const response = await fetch(base + pathname, options);
  return { status: response.status, body: await response.json() };
}

const json = (body, headers = {}) => ({ headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
const admin = { Authorization: `Bearer ${process.env.ADMIN_TOKEN}` };

test('public plan catalog is authoritative', async () => {
  const result = await request('/api/commercial/plans');
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.plans[0], { id: 'pro', name: 'Professional', amount: 99, durationDays: 30, currency: 'TRY' });
});

test('public purchase creates order without exposing email or HWID', async () => {
  const result = await request('/api/payments/iban/orders', { method: 'POST', ...json({ customerId: 'cust-1', customerEmail: 'customer@example.invalid', planId: 'pro', hwid: 'HWID-1' }) });
  assert.equal(result.status, 201);
  assert.equal(result.body.order.amount, 99);
  assert.equal(result.body.order.customerEmail, undefined);
  assert.equal(result.body.order.hwid, undefined);
  assert.equal(result.body.order.license, undefined);
  assert.match(result.body.order.reference, /^ISH-[A-F0-9]{12}$/);
  globalThis.orderId = result.body.order.id;
});

test('admin list is protected and returns pending order', async () => {
  const denied = await request('/api/admin/payments/iban/orders');
  assert.equal(denied.status, 401);
  const allowed = await request('/api/admin/payments/iban/orders', { headers: admin });
  assert.equal(allowed.status, 200);
  assert.equal(allowed.body.orders.length, 1);
  assert.equal(allowed.body.orders[0].status, 'PENDING');
});

test('wrong received amount cannot activate license', async () => {
  const result = await request(`/api/payments/iban/orders/${globalThis.orderId}/confirm`, { method: 'POST', headers: { ...admin, 'content-type': 'application/json' }, body: JSON.stringify({ receivedAmount: 98 }) });
  assert.equal(result.status, 400);
});

test('admin confirmation issues signed license and public activation verifies HWID', async () => {
  const result = await request(`/api/payments/iban/orders/${globalThis.orderId}/confirm`, { method: 'POST', headers: { ...admin, 'content-type': 'application/json' }, body: JSON.stringify({ receivedAmount: 99 }) });
  assert.equal(result.status, 200);
  assert.match(result.body.license, /^ISH-L1\./);
  const valid = await request('/api/licenses/verify', { method: 'POST', ...json({ token: result.body.license, hwid: 'HWID-1' }) });
  assert.equal(valid.status, 200);
  assert.equal(valid.body.valid, true);
  const mismatch = await request('/api/licenses/verify', { method: 'POST', ...json({ token: result.body.license, hwid: 'OTHER-HWID' }) });
  assert.equal(mismatch.status, 200);
  assert.equal(mismatch.body.valid, false);
});

test.after(() => {
  server.close();
  fs.rmSync(dataDir, { recursive: true, force: true });
});
