import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ishv4-ishlock-'));
process.env.ISHV4_DATA_DIR = dataDir;

const { encryptForTenant, decryptForTenant } = await import('../services/kmsClient.js');
const { vault } = await import('../src/vault.js');
const { VaultService } = await import('../src/vault-service.js');
const { requestContextMiddleware } = await import('../src/request-context.js');
const { getAuditLogs } = await import('../src/audit.js');

const svc = new VaultService(vault);
const shares = await svc.init(2, 3);
svc.unseal(shares.shares[0].index, shares.shares[0].shareHex, '127.0.0.1');
svc.unseal(shares.shares[1].index, shares.shares[1].shareHex, '127.0.0.1');
await svc.createKey('primary', 'AES-256-GCM', 'default', 'default');

function inContext(tenantId, userId, fn) {
  return new Promise((resolve, reject) => {
    requestContextMiddleware({ headers: {}, tenantId, actorId: userId }, { setHeader() {} }, async () => {
      try { resolve(await fn()); } catch (err) { reject(err); }
    });
  });
}

test('ISHLock valid tenant encrypts and decrypts through VaultService', async () => {
  const enc = await inContext('default', 'ishlock-test', () => encryptForTenant({ tenantId: 'default', alias: 'primary', plaintext: 'hello-ishlock' }));
  assert.equal(enc.algorithm, 'AES-256-GCM');
  assert.ok(enc.ivHex && enc.authTagHex && enc.ciphertextHex && enc.encryptedDekHex);
  assert.notEqual(enc.ciphertextHex, 'hello-ishlock');

  const dec = await inContext('default', 'ishlock-test', () => decryptForTenant({ tenantId: 'default', payload: { ...enc, tenantId: 'default' } }));
  assert.equal(dec.plaintext, 'hello-ishlock');
});

test('ISHLock rejects cross-tenant access and client tenant override', async () => {
  await assert.rejects(
    () => inContext('default', 'ishlock-test', () => encryptForTenant({ tenantId: 'tenantB', alias: 'primary', plaintext: 'x' })),
    err => err.code === 'TENANT_CONTEXT_MISMATCH'
  );
});

test('ISHLock rejects missing trusted tenant context', async () => {
  await assert.rejects(
    () => encryptForTenant({ tenantId: 'default', alias: 'primary', plaintext: 'x' }),
    err => err.code === 'TENANT_CONTEXT_REQUIRED'
  );
});

test('ISHLock rejects tampered ciphertext', async () => {
  const enc = await inContext('default', 'ishlock-test', () => encryptForTenant({ tenantId: 'default', alias: 'primary', plaintext: 'tamper-me' }));
  const tampered = { ...enc, tenantId: 'default', ciphertextHex: `${enc.ciphertextHex.slice(0, -2)}00` };
  await assert.rejects(
    () => inContext('default', 'ishlock-test', () => decryptForTenant({ tenantId: 'default', payload: tampered })),
    err => err.code === 'CRYPTO_DECRYPT_AUTH_FAILED'
  );
});

test('ISHLock rejects oversized plaintext and invalid payload', async () => {
  await assert.rejects(
    () => inContext('default', 'ishlock-test', () => encryptForTenant({ tenantId: 'default', alias: 'primary', plaintext: 'x'.repeat(256 * 1024 + 1) })),
    err => err.code === 'ISHLOCK_INVALID_INPUT'
  );
  await assert.rejects(
    () => inContext('default', 'ishlock-test', () => decryptForTenant({ tenantId: 'default', payload: null })),
    err => err.code === 'ISHLOCK_INVALID_INPUT'
  );
});

test('ISHLock audit output contains no supplied API key or plaintext', () => {
  const serialized = JSON.stringify(getAuditLogs(100));
  assert.doesNotMatch(serialized, /hello-ishlock|tamper-me/);
  assert.doesNotMatch(serialized, /encryption key|private key|password|token/i);
  assert.match(serialized, /VAULT_WRITE|VAULT_READ/);
});
