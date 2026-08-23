import crypto from 'crypto';
import { splitSecret, combineShares } from './shamir.js';
import { sha256Hex, deriveKek, envelopeEncrypt, envelopeDecrypt, assertPayloadTenant } from './crypto-engine.js';
import { readJson, writeJson } from './store.js';
import { recordAudit, logEvent } from './audit.js';
import { VaultError, TenantError, ValidationError, SystemError } from './errors.js';

const META_FILE = 'vault-meta.json';
const KEYS_FILE = 'keys.json';
const SECRETS_FILE = 'secrets.json';
const DEFAULT_TENANT = 'default';

/**
 * Real Vault/HSM-style engine, with optional Raft-backed HA clustering
 * and real multi-tenant isolation.
 *
 * SECURITY DESIGN (mirrors real HashiCorp Vault integrated-storage HA):
 *  - The master key is NEVER replicated over the network in any form,
 *    encrypted or not. It only ever exists in a node's RAM after an
 *    operator submits real Shamir shares to THAT node's /api/vault/unseal
 *    endpoint directly. In a cluster, every node must be unsealed
 *    individually with the SAME shares - exactly like real Vault.
 *  - What Raft DOES replicate: vault metadata (threshold/verifier hash),
 *    key alias metadata, and already-AES-256-GCM-encrypted secret
 *    records. All of that is safe to replicate because it's either
 *    non-secret metadata or ciphertext that is useless without the
 *    (never-replicated) master key.
 *  - Only the current Raft leader accepts writes. This guarantees a
 *    single, globally ordered sequence of state changes - the same
 *    safety property real distributed KMS/config stores rely on.
 *
 * MULTI-TENANCY: every key and secret record carries a tenantId. The
 * SAME alias name may exist independently in different tenants (e.g.
 * both Tenant A and Tenant B can each have a key called "primary").
 * Isolation is enforced at lookup time - decryptSecretById() rejects
 * any request where the record's tenantId doesn't match the caller's
 * tenantId, even if the secret id itself is guessed/known correctly.
 * tenantId defaults to "default" everywhere so existing single-tenant
 * deployments and callers that don't pass one keep working unchanged.
 */
class VaultEngine {
  constructor() {
    this.meta = readJson(META_FILE, null);
    this.masterKeyHex = null; // only ever lives in RAM, never on disk, never on the wire
    this.pendingShares = new Map();
    this.raft = null; // set via attachRaft() when running in cluster mode
  }

  attachRaft(raftNode) {
    this.raft = raftNode;
  }

  isClustered() {
    return this.raft !== null;
  }

  isInitialized() {
    return !!this.meta;
  }

  isSealed() {
    return !this.masterKeyHex;
  }

  // ---------- INIT ----------
  async init(thresholdK, totalSharesN) {
    if (this.meta) throw new VaultError('Vault already initialized', 'VAULT_ALREADY_INITIALIZED');
    if (!Number.isInteger(thresholdK) || !Number.isInteger(totalSharesN)) {
      throw new ValidationError('thresholdK and totalSharesN must be integers', 'VAULT_INVALID_INIT_PARAMS');
    }

    const masterKeyHex = crypto.randomBytes(32).toString('hex');
    const shares = splitSecret(masterKeyHex, totalSharesN, thresholdK);
    const verifierHash = sha256Hex(masterKeyHex);
    const meta = { initialized: true, thresholdK, totalSharesN, verifierHash, createdAt: new Date().toISOString() };

    if (this.isClustered()) {
      await this.raft.propose({ type: 'VAULT_INIT', meta });
    } else {
      this.applyInit(meta);
    }

    return { shares, thresholdK, totalSharesN };
  }

  applyInit(meta) {
    this.meta = meta;
    writeJson(META_FILE, this.meta);
    writeJson(KEYS_FILE, []);
    writeJson(SECRETS_FILE, []);
    writeJson('tenants.json', [{ tenantId: DEFAULT_TENANT, displayName: 'Default', createdAt: new Date().toISOString() }]);
    recordAudit('operator', 'VAULT_INIT', '/vault/init', 200, 'cluster', `Initialized with ${meta.thresholdK}-of-${meta.totalSharesN} Shamir shares`);
  }

  getStatus() {
    return {
      initialized: this.isInitialized(),
      sealed: this.isSealed(),
      thresholdK: this.meta?.thresholdK ?? null,
      totalSharesN: this.meta?.totalSharesN ?? null,
      sharesSubmitted: this.pendingShares.size,
      activeKeysCount: this.isInitialized() ? readJson(KEYS_FILE, []).length : 0,
      cluster: this.isClustered() ? this.raft.getStatus() : null,
    };
  }

  // ---------- UNSEAL / SEAL (always local-only, never replicated) ----------
  submitUnsealShare(index, shareHex, ip) {
    if (!this.meta) throw new Error('Vault not initialized');
    if (!this.isSealed()) return { sealed: false, message: 'Vault already unsealed' };

    this.pendingShares.set(index, shareHex.trim());

    if (this.pendingShares.size < this.meta.thresholdK) {
      return { sealed: true, sharesSubmitted: this.pendingShares.size, sharesNeeded: this.meta.thresholdK - this.pendingShares.size };
    }

    const shareList = Array.from(this.pendingShares, ([idx, shareHex]) => ({ index: idx, shareHex }));
    let reconstructed;
    try {
      reconstructed = combineShares(shareList);
    } catch (err) {
      this.pendingShares.clear();
      recordAudit('operator', 'VAULT_UNSEAL_FAILED', '/vault/unseal', 400, ip, `Share combination error: ${err.message}`);
      throw new VaultError('Failed to reconstruct key from submitted shares', 'VAULT_UNSEAL_RECONSTRUCT_FAILED');
    }

    const computedHash = sha256Hex(reconstructed);
    const hashesMatch =
      computedHash.length === this.meta.verifierHash.length &&
      crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(this.meta.verifierHash));
    if (!hashesMatch) {
      this.pendingShares.clear();
      recordAudit('operator', 'VAULT_UNSEAL_FAILED', '/vault/unseal', 400, ip, 'Reconstructed key failed verifier check - wrong/insufficient shares');
      throw new VaultError('Reconstructed key does not match vault verifier. Wrong shares submitted.', 'VAULT_UNSEAL_INVALID_SHARES');
    }

    this.masterKeyHex = reconstructed;
    this.pendingShares.clear();
    recordAudit('operator', 'VAULT_UNSEAL_SUCCESS', '/vault/unseal', 200, ip, 'Master key correctly reconstructed and verified (local to this node)');
    return { sealed: false, sharesSubmitted: this.meta.thresholdK };
  }

  seal(ip) {
    this.masterKeyHex = null;
    this.pendingShares.clear();
    recordAudit('operator', 'VAULT_SEALED', '/vault/seal', 200, ip, 'Master key wiped from RAM (local to this node)');
  }

  requireUnsealed() {
    if (!this.meta) throw new VaultError('Vault not initialized', 'VAULT_NOT_INITIALIZED');
    if (this.isSealed()) {
      throw new VaultError('Vault is sealed on this node. Submit threshold Shamir shares to /api/vault/unseal on THIS node first.', 'VAULT_SEALED', 503);
    }
  }

  // ---------- Named key (KEK alias) management, tenant-scoped ----------
  async createKey(alias, algorithm = 'AES-256-GCM', tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const keys = readJson(KEYS_FILE, []);
    if (keys.find((k) => k.alias === alias && k.tenantId === tenantId)) {
      throw new VaultError(`Key alias "${alias}" already exists for tenant "${tenantId}"`, 'VAULT_KEY_ALREADY_EXISTS', 409);
    }

    const result = this.isClustered()
      ? await this.raft.propose({ type: 'CREATE_KEY', alias, algorithm, tenantId })
      : this.applyCreateKey({ alias, algorithm, tenantId });
    logEvent({ action: 'VAULT_WRITE', status: 'SUCCESS', resourcePath: `/vault/keys/${alias}`, tenantId, userId: 'system', details: `operation=create algorithm=${result.algorithm}` });
    return result;
  }

  applyCreateKey({ alias, algorithm, tenantId = DEFAULT_TENANT }) {
    const keys = readJson(KEYS_FILE, []);
    const existing = keys.find((k) => k.alias === alias && k.tenantId === tenantId);
    if (existing) return existing; // idempotent re-apply
    const record = { alias, algorithm, tenantId, version: 1, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    keys.push(record);
    writeJson(KEYS_FILE, keys);
    return record;
  }

  listKeys(tenantId = DEFAULT_TENANT) {
    const result = readJson(KEYS_FILE, []).filter((k) => k.tenantId === tenantId);
    logEvent({ action: 'VAULT_READ', status: 'SUCCESS', resourcePath: '/vault/keys', tenantId, userId: 'system', details: `operation=list count=${result.length}` });
    return result;
  }

  async rotateKey(alias, tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const keys = readJson(KEYS_FILE, []);
    if (!keys.find((k) => k.alias === alias && k.tenantId === tenantId)) {
      throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    }

    const result = this.isClustered()
      ? await this.raft.propose({ type: 'ROTATE_KEY', alias, tenantId })
      : this.applyRotateKey({ alias, tenantId });
    logEvent({ action: 'VAULT_WRITE', status: 'SUCCESS', resourcePath: `/vault/keys/${alias}`, tenantId, userId: 'system', details: `operation=rotate version=${result.version}` });
    return result;
  }

  applyRotateKey({ alias, tenantId = DEFAULT_TENANT }) {
    const keys = readJson(KEYS_FILE, []);
    const key = keys.find((k) => k.alias === alias && k.tenantId === tenantId);
    if (!key) throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    key.version += 1;
    key.updatedAt = new Date().toISOString();
    writeJson(KEYS_FILE, keys);
    return key;
  }

  // Revocation blocks FUTURE encrypt operations with this alias, but
  // deliberately does NOT delete already-encrypted data - a revoked key
  // must still be able to decrypt existing ciphertext (otherwise
  // "revoke" would silently become "destroy", a much more dangerous and
  // often unintended operation). Real key destruction is a separate,
  // deliberate, documented procedure - see KEY-LIFECYCLE-PROCEDURES.md.
  async revokeKey(alias, reason, tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const keys = readJson(KEYS_FILE, []);
    if (!keys.find((k) => k.alias === alias && k.tenantId === tenantId)) {
      throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    }

    const result = this.isClustered()
      ? await this.raft.propose({ type: 'REVOKE_KEY', alias, reason, tenantId })
      : this.applyRevokeKey({ alias, reason, tenantId });
    logEvent({ action: 'VAULT_WRITE', status: 'SUCCESS', resourcePath: `/vault/keys/${alias}`, tenantId, userId: 'system', details: 'operation=revoke' });
    return result;
  }

  applyRevokeKey({ alias, reason, tenantId = DEFAULT_TENANT }) {
    const keys = readJson(KEYS_FILE, []);
    const key = keys.find((k) => k.alias === alias && k.tenantId === tenantId);
    if (!key) throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    key.revoked = true;
    key.revokedAt = new Date().toISOString();
    key.revokedReason = reason || null;
    writeJson(KEYS_FILE, keys);
    return key;
  }

  async setKeyExpiry(alias, expiresAt, tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const keys = readJson(KEYS_FILE, []);
    if (!keys.find((k) => k.alias === alias && k.tenantId === tenantId)) {
      throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    }
    if (expiresAt !== null && Number.isNaN(new Date(expiresAt).getTime())) {
      throw new ValidationError(`Invalid expiresAt date: "${expiresAt}"`, 'VAULT_INVALID_EXPIRY_DATE');
    }

    if (this.isClustered()) {
      return this.raft.propose({ type: 'SET_KEY_EXPIRY', alias, expiresAt, tenantId });
    }
    return this.applySetKeyExpiry({ alias, expiresAt, tenantId });
  }

  applySetKeyExpiry({ alias, expiresAt, tenantId = DEFAULT_TENANT }) {
    const keys = readJson(KEYS_FILE, []);
    const key = keys.find((k) => k.alias === alias && k.tenantId === tenantId);
    if (!key) throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}"`, 'VAULT_KEY_NOT_FOUND', 404);
    key.expiresAt = expiresAt;
    writeJson(KEYS_FILE, keys);
    return key;
  }

  assertKeyUsableForEncryption(key) {
    if (key.revoked) throw new VaultError(`Key "${key.alias}" was revoked${key.revokedReason ? ': ' + key.revokedReason : ''} and cannot be used for new encryption`, 'VAULT_KEY_REVOKED');
    if (key.expiresAt && new Date(key.expiresAt) < new Date()) throw new VaultError(`Key "${key.alias}" expired at ${key.expiresAt} and cannot be used for new encryption`, 'VAULT_KEY_EXPIRED');
  }

  // ---------- Secret encrypt/decrypt, tenant-scoped ----------
  async encryptSecret(alias, plaintext, algorithm, aad, tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const keys = readJson(KEYS_FILE, []);
    const key = keys.find((k) => k.alias === alias && k.tenantId === tenantId);
    if (!key) throw new VaultError(`Key alias "${alias}" not found for tenant "${tenantId}". Create it first via POST /api/kms/keys`, 'VAULT_KEY_NOT_FOUND', 404);
    this.assertKeyUsableForEncryption(key);

    // KEK derivation is scoped by tenantId+alias so two tenants with an
    // identically-named key alias get CRYPTOGRAPHICALLY DIFFERENT keys,
    // not just logically-separated database rows.
    const payload = envelopeEncrypt(plaintext, `${tenantId}:${alias}`, key.version, this.masterKeyHex, algorithm || key.algorithm, aad, tenantId);
    const id = `sec_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const record = { id, tenantId, ...payload, createdAt: new Date().toISOString() };

    if (this.isClustered()) {
      await this.raft.propose({ type: 'STORE_SECRET', record });
    } else {
      this.applyStoreSecret({ record });
    }
    logEvent({ action: 'VAULT_WRITE', status: 'SUCCESS', resourcePath: `/vault/secrets/${id}`, tenantId, userId: 'system', details: 'operation=encrypt-and-store' });
    return record;
  }

  applyStoreSecret({ record }) {
    const secrets = readJson(SECRETS_FILE, []);
    if (!secrets.find((s) => s.id === record.id)) secrets.push(record);
    writeJson(SECRETS_FILE, secrets);
    return record;
  }

  // Real isolation enforcement point: even if an attacker from Tenant B
  // correctly guesses/knows a Tenant A secret id, the tenantId check
  // below rejects it - this is not just a listing/UI-level filter, it's
  // enforced at the point where decryption would otherwise succeed.
  decryptSecretById(id, tenantId = DEFAULT_TENANT) {
    this.requireUnsealed();
    const secrets = readJson(SECRETS_FILE, []);
    const record = secrets.find((s) => s.id === id);
    if (!record) throw new VaultError(`No stored secret with id "${id}" on this node (check it has caught up via replication)`, 'VAULT_SECRET_NOT_FOUND', 404);
    if (record.tenantId !== tenantId) {
      logEvent({ action: 'VAULT_READ', status: 'FAIL', resourcePath: `/vault/secrets/${id}`, tenantId, userId: 'system', errorCode: 'TENANT_CROSS_ACCESS_DENIED', details: 'cross-tenant secret access denied' });
      throw new TenantError(`Secret "${id}" does not belong to tenant "${tenantId}"`, 'TENANT_CROSS_ACCESS_DENIED');
    }
    const result = envelopeDecrypt(record, this.masterKeyHex);
    logEvent({ action: 'VAULT_READ', status: 'SUCCESS', resourcePath: `/vault/secrets/${id}`, tenantId, userId: 'system', details: 'operation=decrypt' });
    return result;
  }

  decryptPayload(payload, tenantId = null) {
    this.requireUnsealed();
    if (tenantId !== null) assertPayloadTenant(payload, tenantId);
    const result = envelopeDecrypt(payload, this.masterKeyHex);
    logEvent({ action: 'VAULT_READ', status: 'SUCCESS', resourcePath: '/vault/secrets/inline', userId: 'system', details: 'operation=decrypt-inline' });
    return result;
  }

  listSecrets(tenantId = DEFAULT_TENANT) {
    const result = readJson(SECRETS_FILE, [])
      .filter((s) => s.tenantId === tenantId)
      .map(({ ciphertextHex, encryptedDekHex, ...meta }) => meta);
    logEvent({ action: 'VAULT_READ', status: 'SUCCESS', resourcePath: '/vault/secrets', tenantId, userId: 'system', details: `operation=list count=${result.length}` });
    return result;
  }

  // ---------- Cluster command dispatcher (used by the Raft onApply callback) ----------
  applyClusterCommand(command) {
    switch (command.type) {
      case 'VAULT_INIT': return this.applyInit(command.meta);
      case 'CREATE_KEY': return this.applyCreateKey(command);
      case 'ROTATE_KEY': return this.applyRotateKey(command);
      case 'REVOKE_KEY': return this.applyRevokeKey(command);
      case 'SET_KEY_EXPIRY': return this.applySetKeyExpiry(command);
      case 'STORE_SECRET': return this.applyStoreSecret(command);
      default: throw new SystemError(`Unknown cluster command type: ${command.type}`, 'VAULT_UNKNOWN_CLUSTER_COMMAND');
    }
  }
}

export const vault = new VaultEngine();
