import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const tmp = fs.mkdtempSync(
  path.join(os.tmpdir(), 'ishv4-reg-')
);

process.env.ISHV4_DATA_DIR = tmp;
process.env.AUDIT_MAX_BYTES = '10485760';

test('crypto roundtrip/AAD/tamper', async () => {
  const {
    envelopeEncrypt,
    envelopeDecrypt
  } = await import('../src/crypto-engine.js');

  const masterKey = crypto.randomBytes(32).toString('hex');

  const payload = envelopeEncrypt(
    'secret',
    'tenantA:k',
    1,
    masterKey,
    'AES-256-GCM',
    'aad',
    'tenantA'
  );

  assert.equal(
    envelopeDecrypt(payload, masterKey).plaintext,
    'secret'
  );

  const tamperedCiphertextHex =
    (
      (parseInt(payload.ciphertextHex[0], 16) ^ 1)
        .toString(16)
    ) +
    payload.ciphertextHex.slice(1);

  assert.notEqual(
    tamperedCiphertextHex,
    payload.ciphertextHex
  );

  assert.throws(() =>
    envelopeDecrypt(
      {
        ...payload,
        ciphertextHex: tamperedCiphertextHex
      },
      masterKey
    )
  );

  assert.throws(() =>
    envelopeDecrypt(
      {
        ...payload,
        aad: 'bad'
      },
      masterKey
    )
  );
});

test('crypto tenant binding', async () => {
  const {
    envelopeEncrypt,
    assertPayloadTenant
  } = await import('../src/crypto-engine.js');

  const payload = envelopeEncrypt(
    'x',
    'tenantA:k',
    1,
    crypto.randomBytes(32).toString('hex'),
    'AES-256-GCM',
    null,
    'tenantA'
  );

  assert.equal(
    assertPayloadTenant(payload, 'tenantA'),
    true
  );

  assert.throws(() =>
    assertPayloadTenant(payload, 'tenantB')
  );
});

test('crypto IV uniqueness', async () => {
  const {
    envelopeEncrypt
  } = await import('../src/crypto-engine.js');

  const masterKey = crypto.randomBytes(32).toString('hex');

  const ivs = new Set(
    Array.from(
      { length: 50 },
      () =>
        envelopeEncrypt(
          'x',
          't:k',
          1,
          masterKey
        ).ivHex
    )
  );

  assert.equal(ivs.size, 50);
});

test('audit chain survives failure event', async () => {
  const {
    recordAudit,
    verifyAuditChain
  } = await import('../src/audit.js');

  recordAudit(
    'u',
    'AUTH_FAIL',
    '/login',
    401,
    '127.0.0.1',
    'invalid',
    {
      tenantId: 't',
      userId: 'u',
      errorCode: 'AUTH_INVALID'
    }
  );

  assert.equal(
    verifyAuditChain().isValid,
    true
  );
});

test('abuse controls statically present', () => {
  const serverSource = fs.readFileSync(
    'server.js',
    'utf8'
  );

  const rateLimitSource = fs.readFileSync(
    'src/anomaly-rate-limit.js',
    'utf8'
  );

  assert.match(
    serverSource,
    /express\.json\(\{ limit: config\.BODY_LIMIT \}/
  );

  assert.match(
    serverSource,
    /rateLimitMiddleware/
  );

  assert.match(
    rateLimitSource,
    /BUCKET_CAPACITY/
  );

  assert.match(
    rateLimitSource,
    /Z_SCORE_THRESHOLD/
  );
});

test('no runtime secret files', () => {
  for (const file of [
    'data/audit.key',
    'data/keys.json',
    'data/secrets.json',
    'data/iam-users.json'
  ]) {
    assert.equal(
      fs.existsSync(file),
      false
    );
  }
});

test('audit rotation preserves segment continuity', () => {
  const dataDir = fs.mkdtempSync(
    path.join(
      os.tmpdir(),
      'ishv4-rotation-'
    )
  );

  const script = `
import fs from 'fs';

const {
  logEvent,
  verifyAuditChain
} = await import('./src/audit.js');

for (let i = 0; i < 20; i++) {
  logEvent({
    action: 'ROTATION_TEST',
    tenantId: 't',
    userId: 'u',
    details: 'x'.repeat(120)
  });
}

const currentPath = ${JSON.stringify(
    path.join(dataDir, 'audit.log')
  )};

const rotatedPath = ${JSON.stringify(
    path.join(dataDir, 'audit.log.1')
  )};

const current = fs.readFileSync(
  currentPath,
  'utf8'
);

const rotated = fs.readFileSync(
  rotatedPath,
  'utf8'
);

console.log(
  JSON.stringify({
    verify: verifyAuditChain(),
    current: current
      .split(String.fromCharCode(10))
      .filter(Boolean)
      .length,
    rotated: rotated
      .split(String.fromCharCode(10))
      .filter(Boolean)
      .length
  })
);
`;

  const out = execFileSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      script
    ],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        ISHV4_DATA_DIR: dataDir,
        AUDIT_MAX_BYTES: '3000'
      },
      encoding: 'utf8'
    }
  );

  const result = JSON.parse(
    out.trim()
  );

  assert.equal(
    result.verify.isValid,
    true
  );

  assert.ok(
    result.current > 0
  );

  assert.ok(
    result.rotated > 0
  );

  fs.rmSync(
    dataDir,
    {
      recursive: true,
      force: true
    }
  );
});