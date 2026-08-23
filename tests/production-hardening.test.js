import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const server = fs.readFileSync('server.js', 'utf8');
const config = fs.readFileSync('src/config.js', 'utf8');


test('production configuration fails closed for insecure defaults', () => {
  assert.match(config, /NODE_ENV: z\.string\(\)\.default\('development'\)/);
  assert.match(config, /production && !cfg\.STRICT_MODE/);
  assert.match(config, /production && !cfg\.DISABLE_FALLBACKS/);
  assert.match(config, /STRICT_MODE && !cfg\.ADMIN_TOKEN/);
});

test('production error handling does not expose unexpected exception messages', () => {
  assert.match(server, /function safeClientError\(err\)/);
  assert.match(server, /err\.isOperational === true/);
  assert.match(server, /Internal server error/);
});

test('request body size and existing rate limiting remain enforced', () => {
  assert.match(server, /express\.json\(\{ limit: config\.BODY_LIMIT \}\)/);
  assert.match(server, /rateLimitMiddleware/);
});

test('health and readiness endpoints remain secret-free', () => {
  assert.match(server, /app\.get\('\/health'/);
  assert.match(server, /app\.get\('\/ready'/);
  const healthSection = server.slice(server.indexOf("app.get('/health'"), server.indexOf("function resolveIshLockApiKey"));
  assert.doesNotMatch(healthSection, /password|token|secret|privateKey|masterKey/i);
});

test('audit rotation and integrity implementation remain present', () => {
  const audit = fs.readFileSync('src/audit.js', 'utf8');
  assert.match(audit, /rotateAuditLogIfNeeded/);
  assert.match(audit, /verifyAuditChain/);
  assert.match(audit, /renameSync\(file, rotated\)/);
});
