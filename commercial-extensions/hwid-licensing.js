import crypto from 'crypto';
import os from 'os';
import { readJson, writeJson } from '../src/store.js';

/**
 * Hardware-ID based license enforcement.
 *
 * ISOLATION NOTE: this module lives in commercial-extensions/, not
 * src/. It is only invoked if the "hwid-licensing" module is explicitly
 * enabled via the module registry (off by default). A government/
 * certification deployment never touches this file.
 *
 * The "hardware ID" here is a real, deterministic fingerprint derived
 * from actual OS-reported machine characteristics (not a placeholder) -
 * hostname + platform + CPU model + total memory, SHA-256 hashed. This
 * is the same general technique commercial software licensing uses
 * (e.g. tying a license to a specific machine). It changes if run on
 * different hardware, which is the whole point.
 */

const LICENSES_FILE = 'hwid-licenses.json';

export function computeHwid() {
  const cpus = os.cpus();
  const fingerprint = [
    os.hostname(),
    os.platform(),
    os.arch(),
    cpus[0]?.model || 'unknown-cpu',
    cpus.length,
    Math.round(os.totalmem() / (1024 * 1024 * 1024)), // GB, rounded (survives minor memory reporting variance)
  ].join('|');
  return crypto.createHash('sha256').update(fingerprint).digest('hex');
}

export function issueLicense(licenseKey, hwid, expiresAt) {
  const licenses = readJson(LICENSES_FILE, {});
  licenses[licenseKey] = { hwid, expiresAt: expiresAt || null, issuedAt: new Date().toISOString() };
  writeJson(LICENSES_FILE, licenses);
  return licenses[licenseKey];
}

export function verifyLicense(licenseKey) {
  const licenses = readJson(LICENSES_FILE, {});
  const record = licenses[licenseKey];
  if (!record) return { valid: false, reason: 'License key not found' };

  const currentHwid = computeHwid();
  if (record.hwid !== currentHwid) {
    return { valid: false, reason: 'License is bound to a different machine (HWID mismatch)' };
  }
  if (record.expiresAt && new Date(record.expiresAt) < new Date()) {
    return { valid: false, reason: 'License expired' };
  }
  return { valid: true, hwid: currentHwid };
}

export function licenseMiddleware(getIsEnabled) {
  return (req, res, next) => {
    if (!getIsEnabled()) return next(); // module disabled -> no-op, does not affect core

    const licenseKey = req.headers['x-license-key'];
    if (!licenseKey) return res.status(402).json({ error: 'License key required (X-License-Key header)' });

    const result = verifyLicense(licenseKey);
    if (!result.valid) return res.status(402).json({ error: 'Invalid license', reason: result.reason });

    next();
  };
}
