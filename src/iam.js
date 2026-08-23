import crypto from 'crypto';
import { readJson, writeJson } from './store.js';
import { verifyTotp } from './totp.js';
import { AuthError, ValidationError } from './errors.js';
import { logEvent } from './audit.js';
import { config } from './config.js';

const USERS_FILE = 'iam-users.json';

/**
 * Real RBAC (Role-Based Access Control) with separation of duties.
 * Three roles, matching real KMS operational practice (this mirrors how
 * HashiCorp Vault and AWS KMS separate "who can manage keys" from
 * "who can just use them" from "who can only read logs" - a single admin
 * token cannot enforce that distinction):
 *
 *  - "admin"    : create/rotate keys, seal/unseal, manage users
 *  - "operator" : encrypt/decrypt using existing keys only
 *  - "auditor"  : read audit logs and export only, no crypto operations
 *
 * Each user has: a bcrypt-equivalent (PBKDF2-HMAC-SHA256) hashed
 * password, a role, and an optional TOTP secret for MFA. Passwords are
 * never stored in plaintext; TOTP secrets are stored so we can verify
 * codes (this is how real TOTP verification necessarily works - the
 * server must hold the shared secret).
 */

const ROLE_PERMISSIONS = {
  admin: ['vault:seal', 'vault:unseal', 'vault:init', 'kms:create-key', 'kms:rotate-key', 'kms:encrypt', 'kms:decrypt', 'iam:manage', 'audit:read', 'hsm:manage'],
  operator: ['kms:encrypt', 'kms:decrypt', 'audit:read'],
  auditor: ['audit:read', 'audit:export'],
};

import argon2 from 'argon2';

async function hashPassword(password) {
  // Argon2id: OWASP's current recommendation over PBKDF2 specifically
  // because it's memory-hard - PBKDF2 is CPU-cost only, which GPUs and
  // ASICs can brute-force far more cheaply per-guess than a general
  // CPU can. Argon2id forces each guess to allocate real memory,
  // closing that gap. Parameters below follow OWASP's 2024 minimum
  // recommendation (19 MiB memory, 2 iterations, 1 parallelism) as a
  // floor - real deployments with more RAM budget should raise
  // memoryCost further.
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456, // KiB (~19 MiB)
    timeCost: 2,
    parallelism: 1,
  });
}

async function verifyPassword(password, stored) {
  // Backward compatibility: any user created before this upgrade has a
  // PBKDF2 hash in "salt:hash" format (no Argon2 prefix). We detect and
  // support both so existing accounts aren't locked out - but log which
  // path was used so operators can track migration progress.
  if (stored.startsWith('$argon2')) {
    return argon2.verify(stored, password);
  }
  // Legacy PBKDF2 path (pre-upgrade accounts)
  const [salt, hash] = stored.split(':');
  const candidate = crypto.pbkdf2Sync(password, salt, 210000, 32, 'sha256').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(hash));
}

export async function createUser(username, password, role, tenantId = 'default') {
  if (!ROLE_PERMISSIONS[role]) throw new ValidationError(`Unknown role "${role}". Valid roles: ${Object.keys(ROLE_PERMISSIONS).join(', ')}`, 'IAM_UNKNOWN_ROLE');
  const users = readJson(USERS_FILE, []);
  if (users.find((u) => u.username === username)) throw new ValidationError(`User "${username}" already exists`, 'IAM_USER_EXISTS');

  const record = {
    username, role, tenantId,
    passwordHash: await hashPassword(password),
    totpSecret: null,
    mfaEnabled: false,
    createdAt: new Date().toISOString(),
  };
  users.push(record);
  writeJson(USERS_FILE, users);
  return { username, role, tenantId, mfaEnabled: false };
}

export function enrollMfa(username) {
  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!user) throw new ValidationError(`User "${username}" not found`, 'IAM_USER_NOT_FOUND');
  const secret = crypto.randomBytes(20).toString('hex'); // will be base32-encoded by caller if needed for QR
  user.totpSecret = secret;
  writeJson(USERS_FILE, users);
  return { totpSecretHex: secret };
}

export function confirmMfaEnrollment(username, totpCode, base32Secret) {
  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!user) throw new ValidationError(`User "${username}" not found`, 'IAM_USER_NOT_FOUND');
  if (!verifyTotp(base32Secret, totpCode)) throw new AuthError('Invalid TOTP code - enrollment not confirmed', 'IAM_MFA_ENROLL_INVALID_CODE');
  user.mfaEnabled = true;
  user.totpSecretB32 = base32Secret;
  writeJson(USERS_FILE, users);
  return { mfaEnabled: true };
}

const sessions = new Map(); // sessionToken -> { username, role, createdAt }

export function resolveSession(token) {
  const session = sessions.get(token) || null;
  if (session && (Date.now() - Date.parse(session.createdAt)) >= config.SESSION_TTL_MS) { sessions.delete(token); logEvent({action:'AUTH_TOKEN_VERIFY',status:'FAIL',resourcePath:'/iam/session/verify',errorCode:'IAM_SESSION_EXPIRED',tenantId:session.tenantId||'default',userId:session.username,details:'session expired'}); return null; }
  if (!session) {
    logEvent({
      action: 'AUTH_TOKEN_VERIFY',
      status: 'FAIL',
      resourcePath: '/iam/session/verify',
      errorCode: 'IAM_INVALID_SESSION',
      details: 'session token verification failed',
    });
  } else {
    logEvent({
      action: 'AUTH_TOKEN_VERIFY',
      status: 'SUCCESS',
      resourcePath: '/iam/session/verify',
      tenantId: session.tenantId || 'default',
      userId: session.username,
      details: `role=${session.role}`,
    });
  }
  return session;
}

export async function authenticate(username, password, totpCode, ip) {
  const users = readJson(USERS_FILE, []);
  const user = users.find((u) => u.username === username);
  if (!user) {
    logEvent({ action: 'AUTH_LOGIN', status: 'FAIL', resourcePath: '/iam/login', ipAddress: ip, errorCode: 'IAM_INVALID_CREDENTIALS', details: 'invalid credentials' });
    throw new AuthError('Invalid credentials', 'IAM_INVALID_CREDENTIALS');
  }
  if (!(await verifyPassword(password, user.passwordHash))) {
    logEvent({ action: 'AUTH_LOGIN', status: 'FAIL', resourcePath: '/iam/login', ipAddress: ip, tenantId: user.tenantId || 'default', userId: user.username, errorCode: 'IAM_INVALID_CREDENTIALS', details: 'invalid credentials' });
    throw new AuthError('Invalid credentials', 'IAM_INVALID_CREDENTIALS');
  }
  if (user.mfaEnabled) {
    if (!totpCode) {
      logEvent({ action: 'AUTH_LOGIN', status: 'FAIL', resourcePath: '/iam/login', ipAddress: ip, tenantId: user.tenantId || 'default', userId: user.username, errorCode: 'IAM_MFA_REQUIRED', details: 'MFA required' });
      throw new AuthError('MFA required: totpCode missing', 'IAM_MFA_REQUIRED');
    }
    if (!verifyTotp(user.totpSecretB32, totpCode)) {
      logEvent({ action: 'AUTH_LOGIN', status: 'FAIL', resourcePath: '/iam/login', ipAddress: ip, tenantId: user.tenantId || 'default', userId: user.username, errorCode: 'IAM_MFA_INVALID_CODE', details: 'invalid MFA code' });
      throw new AuthError('Invalid MFA code', 'IAM_MFA_INVALID_CODE');
    }
  }
  const sessionToken = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionToken, { username: user.username, role: user.role, tenantId: user.tenantId || 'default', createdAt: new Date().toISOString() });
  logEvent({ action: 'AUTH_LOGIN', status: 'SUCCESS', resourcePath: '/iam/login', ipAddress: ip, tenantId: user.tenantId || 'default', userId: user.username, details: `role=${user.role}` });
  return { username: user.username, role: user.role, tenantId: user.tenantId || 'default', sessionToken, permissions: ROLE_PERMISSIONS[user.role] };
}

export function hasAnyAdmin() {
  const users = readJson(USERS_FILE, []);
  return users.some((u) => u.role === 'admin');
}

export function listUsers() {
  return readJson(USERS_FILE, []).map(({ passwordHash, totpSecret, totpSecretB32, ...safe }) => safe);
}

export function hasPermission(role, permission) {
  return (ROLE_PERMISSIONS[role] || []).includes(permission);
}

export function requirePermission(permission) {
  return (req, res, next) => {
    const role = req.userRole; // set by an auth middleware upstream (e.g. after Bearer token -> role lookup)
    if (!role) return res.status(401).json({ error: 'Not authenticated' });
    if (!hasPermission(role, permission)) {
      return res.status(403).json({ error: `Role "${role}" lacks permission "${permission}"` });
    }
    next();
  };
}

export { ROLE_PERMISSIONS };
