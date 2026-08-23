import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const source = fs.readFileSync('security/spywareDefender.js', 'utf8');

import { after } from 'node:test';
after(() => {
  for (const file of ['data/audit.key', 'data/audit.log', 'data/audit.log.1']) {
    try { fs.rmSync(file, { force: true }); } catch {}
  }
});

function inContext(tenantId, userId, fn) {
  return new Promise((resolve, reject) => {
    import('../src/request-context.js').then(({ requestContextMiddleware }) => {
      requestContextMiddleware({ headers: {}, tenantId, actorId: userId }, { setHeader() {} }, async () => {
        try { resolve(await fn()); } catch (err) { reject(err); }
      });
    }).catch(reject);
  });
}

test('anti-spyware module loads and returns required schema', async () => {
  const { runSpywareDefender } = await import('../security/spywareDefender.js');
  const result = await inContext('default', 'anti-spyware-test', () => runSpywareDefender());
  for (const key of ['compromised', 'rootDetected', 'suspiciousProcesses', 'networkAlerts', 'persistenceFindings']) assert.ok(key in result);
  assert.ok(typeof result.compromised === 'boolean');
  assert.ok(result.rootDetected === null || typeof result.rootDetected === 'boolean');
  assert.ok(Array.isArray(result.suspiciousProcesses));
  assert.ok(Array.isArray(result.networkAlerts));
  assert.ok(Array.isArray(result.persistenceFindings));
});

test('real process/network/persistence probes execute without destructive actions', async () => {
  const { runSpywareDefender } = await import('../security/spywareDefender.js');
  const result = await inContext('default', 'anti-spyware-runtime', () => runSpywareDefender());
  assert.ok(Array.isArray(result.suspiciousProcesses));
  assert.ok(Array.isArray(result.networkAlerts));
  assert.ok(Array.isArray(result.persistenceFindings));
  assert.match(source, /scanProcesses\(\)/);
  assert.match(source, /scanNetwork\(\)/);
  assert.match(source, /scanFiles\(/);
});

test('file integrity uses real SHA-256 via existing file scanner', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ishv4-spyware-'));
  const file = path.join(dir, 'sample.txt');
  const content = 'ishv4-anti-spyware-integrity';
  fs.writeFileSync(file, content);
  const { hashFile } = await import('../security-agent/fileScanner.js');
  assert.equal(hashFile(file), crypto.createHash('sha256').update(content).digest('hex'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('tenant context is required and client tenant cannot override trusted context', async () => {
  const { runSpywareDefender } = await import('../security/spywareDefender.js');
  assert.throws(() => runSpywareDefender({ tenantId: 'default' }), err => err.code === 'TENANT_CONTEXT_REQUIRED');
  await assert.rejects(
    () => inContext('tenantA', 'userA', () => runSpywareDefender({ tenantId: 'tenantB' })),
    err => err.code === 'TENANT_CONTEXT_MISMATCH'
  );
});

test('concurrent request contexts remain isolated', async () => {
  const { runSpywareDefender } = await import('../security/spywareDefender.js');
  const { getRequestContext } = await import('../src/request-context.js');
  const run = (tenantId, userId, delay) => inContext(tenantId, userId, async () => {
    await new Promise(r => setTimeout(r, delay));
    const result = runSpywareDefender({ tenantId });
    return { result, context: getRequestContext() };
  });
  const [a, b] = await Promise.all([run('tenantA', 'userA', 10), run('tenantB', 'userB', 1)]);
  assert.equal(a.context.tenantId, 'tenantA');
  assert.equal(b.context.tenantId, 'tenantB');
  assert.notEqual(a.context.requestId, b.context.requestId);
});

test('audit event is aggregate and secret-free', async () => {
  const { getAuditLogs } = await import('../src/audit.js');
  const serialized = JSON.stringify(getAuditLogs(50));
  assert.match(serialized, /SPYWARE_DEFENDER_SCAN/);
  assert.doesNotMatch(serialized, /password|token|api[_-]?key|private[_-]?key|ciphertext|plaintext/i);
});

test('destructive operations are absent from anti-spyware implementation', () => {
  assert.doesNotMatch(source, /process\.kill\s*\(/);
  assert.doesNotMatch(source, /kill\s+-9/);
  assert.doesNotMatch(source, /rm\s+-rf/);
  assert.doesNotMatch(source, /fs\.(unlink|rmdir|rmSync)\s*\(/);
  assert.doesNotMatch(source, /shutdown|reboot|format/i);
});

test('spyware route is orchestrated, tenant-bound and admin-protected', () => {
  const server = fs.readFileSync('server.js', 'utf8');
  assert.match(server, /app\.post\('\/api\/security\/spyware-scan', requireAdmin, handle\(orchestrate\('security\.spyware-scan'/);
  assert.match(server, /runSpywareDefender\(\{ paths: req\.body\?\.paths \|\| \[\], tenantId: contextTenant \}\)/);
  assert.match(server, /requireTenant: true/);
});

test('unsupported-platform branches are explicit', () => {
  assert.match(source, /return \{ findings: \[\], supported: false \}/);
  assert.match(source, /return \{ alerts: \[\], supported: false \}/);
  assert.match(source, /detected: null, supported: false/);
});
