import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const DEMO_STATUSES = Object.freeze({
  ACTIVE: 'DEMO_ACTIVE', EXPIRED: 'DEMO_EXPIRED', INVALID: 'INVALID', HWID_MISMATCH: 'HWID_MISMATCH',
  ALREADY_USED: 'DEMO_ALREADY_USED', NOT_CONFIGURED: 'NOT_CONFIGURED', UNAVAILABLE: 'UNAVAILABLE'
});
const DAYS = 7;
const dir = () => process.env.ISH_DEMO_DATA_DIR || path.resolve('./data/demo');
const ledger = () => path.join(dir(), 'issuances.json');
const key = n => { const v = process.env[n]?.trim(); if (!v) throw new Error(`${n} is required`); return v.replace(/\\n/g, '\n'); };
const b64 = v => Buffer.from(v).toString('base64url');
const normalizeEmail = v => String(v || '').trim().toLowerCase();
const fingerprint = v => crypto.createHash('sha256').update(String(v || '')).digest('hex');
function readLedger() { try { return JSON.parse(fs.readFileSync(ledger(), 'utf8')); } catch { return []; } }
function writeLedger(rows) { fs.mkdirSync(dir(), { recursive: true, mode: 0o700 }); fs.writeFileSync(ledger(), JSON.stringify(rows, null, 2), { mode: 0o600 }); }

export function issueDemo({ customerId, email, hwid }) {
  const customerEmail = normalizeEmail(email);
  if (!customerId || !customerEmail || !hwid) throw new Error('customerId, email and HWID are required');
  const rows = readLedger();
  const emailHash = fingerprint(customerEmail), hwidHash = fingerprint(hwid);
  if (rows.some(x => x.emailHash === emailHash || x.hwidHash === hwidHash)) throw new Error(DEMO_STATUSES.ALREADY_USED);
  const now = new Date(), expiresAt = new Date(now.getTime() + DAYS * 86400000);
  const payload = { iss: process.env.ISH_LICENSE_ISSUER || 'ISH', jti: crypto.randomUUID(), customerId, hwid, demo: true, issuedAt: now.toISOString(), expiresAt: expiresAt.toISOString() };
  const encoded = b64(JSON.stringify(payload));
  const privateKey = crypto.createPrivateKey(key('ISH_LICENSE_PRIVATE_KEY'));
  const signature = crypto.sign(null, Buffer.from(encoded), privateKey).toString('base64url');
  rows.push({ jti: payload.jti, emailHash, hwidHash, issuedAt: payload.issuedAt, expiresAt: payload.expiresAt });
  writeLedger(rows);
  return { token: `ISH-D1.${encoded}.${signature}`, status: DEMO_STATUSES.ACTIVE, expiresAt: payload.expiresAt };
}

export function verifyDemo(token, hwid) {
  try {
    const publicKey = crypto.createPublicKey(key('ISH_LICENSE_PUBLIC_KEY'));
    const [prefix, encoded, signature] = String(token || '').split('.');
    if (prefix !== 'ISH-D1' || !encoded || !signature) return { valid: false, status: DEMO_STATUSES.INVALID };
    if (!crypto.verify(null, Buffer.from(encoded), publicKey, Buffer.from(signature, 'base64url'))) return { valid: false, status: DEMO_STATUSES.INVALID };
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (payload.demo !== true) return { valid: false, status: DEMO_STATUSES.INVALID };
    if (hwid && payload.hwid !== hwid) return { valid: false, status: DEMO_STATUSES.HWID_MISMATCH };
    if (new Date(payload.expiresAt) <= new Date()) return { valid: false, status: DEMO_STATUSES.EXPIRED, payload };
    return { valid: true, status: DEMO_STATUSES.ACTIVE, payload };
  } catch { return { valid: false, status: DEMO_STATUSES.NOT_CONFIGURED }; }
}

export function listDemoIssuances() { return readLedger().map(x => ({ ...x })); }
