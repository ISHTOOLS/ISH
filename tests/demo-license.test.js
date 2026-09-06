import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ish-demo-'));
const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
process.env.ISH_DEMO_DATA_DIR = dir;
process.env.ISH_LICENSE_PRIVATE_KEY = privateKey.export({ format: 'pem', type: 'pkcs8' });
process.env.ISH_LICENSE_PUBLIC_KEY = publicKey.export({ format: 'pem', type: 'spki' });
const { issueDemo, verifyDemo } = await import('../commercial-extensions/demo-license.js');

test('issues a seven-day signed demo', () => {
  const result = issueDemo({ customerId: 'demo-1', email: 'demo@example.invalid', hwid: 'HWID-DEMO-1' });
  assert.equal(result.status, 'DEMO_ACTIVE');
  assert.match(result.token, /^ISH-D1\./);
  const verified = verifyDemo(result.token, 'HWID-DEMO-1');
  assert.equal(verified.valid, true);
  assert.equal(verified.status, 'DEMO_ACTIVE');
  const duration = new Date(verified.payload.expiresAt) - new Date(verified.payload.issuedAt);
  assert.equal(duration, 7 * 86400000);
  globalThis.token = result.token;
});

test('rejects HWID mismatch and tampering', () => {
  assert.equal(verifyDemo(globalThis.token, 'OTHER-HWID').status, 'HWID_MISMATCH');
  const parts = globalThis.token.split('.');
  parts[1] = parts[1].slice(0, -1) + (parts[1].endsWith('A') ? 'B' : 'A');
  assert.equal(verifyDemo(parts.join('.'), 'HWID-DEMO-1').status, 'INVALID');
});

test('prevents a second demo for the same email or HWID', () => {
  assert.throws(() => issueDemo({ customerId: 'demo-2', email: 'demo@example.invalid', hwid: 'HWID-DEMO-2' }), /DEMO_ALREADY_USED/);
  assert.throws(() => issueDemo({ customerId: 'demo-3', email: 'other@example.invalid', hwid: 'HWID-DEMO-1' }), /DEMO_ALREADY_USED/);
});

test('expired demo is rejected', () => {
  const encoded = globalThis.token.split('.')[1];
  const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
  payload.expiresAt = new Date(Date.now() - 1000).toISOString();
  const altered = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.sign(null, Buffer.from(altered), privateKey).toString('base64url');
  assert.equal(verifyDemo(`ISH-D1.${altered}.${signature}`, 'HWID-DEMO-1').status, 'DEMO_EXPIRED');
});

test.after(() => fs.rmSync(dir, { recursive: true, force: true }));
