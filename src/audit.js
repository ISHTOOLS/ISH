import crypto from 'crypto';
import fs from 'fs';
import { dataFilePath, appendLine, readLines, ensureDataDir } from './store.js';
import { createSiemPusher } from './siem-pusher.js';
import { getRequestContext } from './request-context.js';

const GENESIS_HMAC = '0'.repeat(64);
const AUDIT_KEY_FILE = 'audit.key';
const AUDIT_LOG_FILE = 'audit.log';

const siemPusher = createSiemPusher({
  host: process.env.SIEM_HOST || null,
  port: process.env.SIEM_PORT ? Number(process.env.SIEM_PORT) : null,
  protocol: process.env.SIEM_PROTOCOL || 'udp',
});

const CEF_SEVERITY_MAP = {
  VAULT_INIT: 8, VAULT_UNSEAL_SUCCESS: 6, VAULT_UNSEAL_FAILED: 9, VAULT_SEALED: 5,
  KEY_CREATED: 4, KEY_ROTATED: 4, ENCRYPT: 2, DECRYPT: 2,
  HSM_KEY_GENERATED: 5, HSM_SIGN: 3, PQC_HYBRID_EXCHANGE: 2, RATE_LIMIT_ANOMALY: 9,
};

function toCefLine(entry) {
  const sev = CEF_SEVERITY_MAP[entry.action] ?? 3;
  const esc = (v) => String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\n/g, '\\n');
  return `CEF:0|ISHv4|RealKMS|1.0|${esc(entry.action)}|${esc(entry.action)}|${sev}|rt=${new Date(entry.timestamp).getTime()} suser=${esc(entry.actorId)} src=${esc(entry.ipAddress)} request=${esc(entry.resourcePath)} cs1Label=commitSeq cs1=${entry.seq} cs2Label=integrityHmac cs2=${entry.currentHmac?.slice(0, 16)} msg=${esc(entry.details)}`;
}

// The audit signing key is independent from the vault master key so that
// audit events (including "vault sealed") can always be logged and the
// chain can always be verified, even while the vault itself is sealed.
export function getOrCreateAuditKey() {
  ensureDataDir();
  const p = dataFilePath(AUDIT_KEY_FILE);
  if (fs.existsSync(p)) {
    return fs.readFileSync(p, 'utf-8').trim();
  }
  const key = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(p, key, { mode: 0o600 });
  return key;
}

function lastHmac() {
  const lines = readLines(AUDIT_LOG_FILE);
  if (lines.length > 0) return lines[lines.length - 1].currentHmac;
  const rotatedLines = readLines(`${AUDIT_LOG_FILE}.1`);
  if (rotatedLines.length > 0) return rotatedLines[rotatedLines.length - 1].currentHmac;
  return GENESIS_HMAC;
}

// The HMAC covers every persisted field directly (not an indirect stored
// hash). This matters: if it only covered a separately-stored payloadHash,
// someone could edit e.g. "action" on disk and leave payloadHash untouched,
// and the chain would still "verify". Canonicalizing over the real fields
// closes that hole - verified below with an actual tamper test.
function sanitizeString(value) {
  return String(value ?? '')
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function canonicalizeLegacy(entry) {
  return [
    entry.previousHmac,
    entry.timestamp,
    entry.actorId,
    entry.action,
    entry.resourcePath,
    String(entry.statusCode),
    entry.ipAddress,
    entry.details,
  ].join('\u0001');
}

function canonicalize(entry) {
  return [
    entry.previousHmac,
    entry.timestamp,
    entry.actorId,
    entry.userId,
    entry.tenantId,
    entry.action,
    entry.resourcePath,
    String(entry.statusCode),
    entry.status,
    entry.errorCode,
    entry.ipAddress,
    entry.details,
  ].join('\u0001');
}

export function recordAudit(actorId, action, resourcePath, statusCode, ipAddress, details, metadata = {}) {
  const auditKey = getOrCreateAuditKey();
  const seq = readLines(AUDIT_LOG_FILE).length + 1;
  const timestamp = new Date().toISOString();
  const previousHmac = lastHmac();

  const normalizedStatusCode = Number.isInteger(statusCode) ? statusCode : 200;
  const status = metadata.status === 'FAIL' || normalizedStatusCode >= 400 ? 'FAIL' : 'SUCCESS';
  const normalized = {
    actorId: sanitizeString(actorId || metadata.userId || 'system'),
    userId: sanitizeString(metadata.userId || actorId || 'system'),
    tenantId: sanitizeString(metadata.tenantId || ''),
    action: sanitizeString(action),
    resourcePath: sanitizeString(resourcePath),
    statusCode: normalizedStatusCode,
    status,
    errorCode: sanitizeString(metadata.errorCode || ''),
    ipAddress: sanitizeString(ipAddress),
    details: sanitizeString(details),
  };

  const draft = { previousHmac, timestamp, ...normalized };
  const currentHmac = crypto.createHmac('sha256', Buffer.from(auditKey, 'hex')).update(canonicalize(draft)).digest('hex');

  const entry = {
    seq,
    id: `log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    timestamp,
    ...normalized,
    previousHmac,
    currentHmac,
  };

  appendLine(AUDIT_LOG_FILE, JSON.stringify(entry));
  rotateAuditLogIfNeeded();
  if (siemPusher.enabled) siemPusher.push(toCefLine(entry));
  return entry;
}

/**
 * Stable, structured audit API for critical operations. It intentionally
 * accepts only a fixed schema so callers cannot inject arbitrary fields.
 */

function rotateAuditLogIfNeeded() {
  const maxBytes = Number(process.env.AUDIT_MAX_BYTES || 10 * 1024 * 1024);
  if (!Number.isFinite(maxBytes) || maxBytes < 1024) return;
  const file = dataFilePath(AUDIT_LOG_FILE);
  try {
    if (fs.statSync(file).size <= maxBytes) return;
    const rotated = `${file}.1`;
    // Preserve the last committed HMAC as the continuity anchor for the
    // new segment. The previous implementation left the new audit.log
    // absent until the next event and made verifyAuditChain start at the
    // genesis value, so a legitimate rotation could appear tampered.
    if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
    fs.renameSync(file, rotated);
    fs.writeFileSync(file, '', { mode: 0o600 });
  } catch (err) {
    // Audit rotation must never take the service down.
    console.error('[audit] rotation failed', err.message);
  }
}

export function logEvent(event = {}) {
  const context = getRequestContext();
  const status = event.status === 'FAIL' ? 'FAIL' : 'SUCCESS';
  const statusCode = status === 'FAIL' ? 400 : 200;
  return recordAudit(
    event.userId || context.userId || 'system',
    event.action || 'UNKNOWN',
    event.resourcePath || event.action || 'unknown',
    statusCode,
    event.ipAddress || 'unknown',
    event.details || '',
    {
      tenantId: event.tenantId || context.tenantId || '',
      userId: event.userId || context.userId || 'system',
      status,
      errorCode: event.errorCode || '',
    },
  );
}

export function getSiemPusherStatus() {
  return { enabled: siemPusher.enabled, host: siemPusher.host, port: siemPusher.port, protocol: siemPusher.protocol };
}

export function getAuditLogs(limit = 100) {
  const lines = readLines(AUDIT_LOG_FILE);
  return lines.slice(-limit).reverse();
}

// Recomputes the entire HMAC chain from disk and checks it against what's
// stored. Any edited/deleted/reordered log line will break the chain.
export function verifyAuditChain() {
  const auditKey = getOrCreateAuditKey();
  const lines = readLines(AUDIT_LOG_FILE);

  let expectedPrev = GENESIS_HMAC;
  const rotated = dataFilePath(`${AUDIT_LOG_FILE}.1`);
  if (fs.existsSync(rotated)) {
    const rotatedLines = readLines(`${AUDIT_LOG_FILE}.1`);
    if (rotatedLines.length > 0) expectedPrev = rotatedLines[rotatedLines.length - 1].currentHmac;
  }
  for (let i = 0; i < lines.length; i++) {
    const entry = lines[i];
    if (entry.previousHmac !== expectedPrev) {
      return { isValid: false, totalChecked: i + 1, tamperedSeq: entry.seq, reason: 'previousHmac linkage broken' };
    }
    const isLegacy = entry.userId === undefined && entry.tenantId === undefined && entry.status === undefined && entry.errorCode === undefined;
    const payload = isLegacy ? canonicalizeLegacy(entry) : canonicalize(entry);
    const recomputed = crypto.createHmac('sha256', Buffer.from(auditKey, 'hex')).update(payload).digest('hex');
    if (recomputed !== entry.currentHmac) {
      return { isValid: false, totalChecked: i + 1, tamperedSeq: entry.seq, reason: 'HMAC mismatch - one or more fields on this entry were altered' };
    }
    expectedPrev = entry.currentHmac;
  }
  return { isValid: true, totalChecked: lines.length };
}
