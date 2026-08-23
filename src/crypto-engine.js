import crypto from 'crypto';
import { CryptoError, ValidationError } from './errors.js';
import { logEvent } from './audit.js';

/**
 * Real cryptographic primitives, all backed by Node's `crypto` module
 * (OpenSSL underneath). Every algorithm name below is what is actually
 * executed - nothing is relabeled to sound more advanced than it is.
 *
 * Included:
 *  - AES-256-GCM / ChaCha20-Poly1305 authenticated envelope encryption
 *  - HKDF-SHA256 key derivation
 *  - Ed25519 digital signatures
 *  - X25519 Diffie-Hellman key exchange
 *
 * NOT included (and NOT claimed):
 *  - ML-KEM / Kyber, ML-DSA / Dilithium, or any other lattice-based
 *    post-quantum algorithm. None of the classical primitives above are
 *    quantum-resistant. See README "Post-Quantum Roadmap" for how to add
 *    real PQC via liboqs if you need it.
 *
 * SECURITY NOTE on deriveKek()'s salt: it is intentionally a FIXED
 * string, not per-operation random. This is correct, not an oversight -
 * per RFC 5869, an HKDF salt does not need to be secret or random when
 * the input keying material (here: the vault master key) is already
 * uniformly random with full entropy (256 bits, from crypto.randomBytes
 * at vault init) - which it is. A fixed salt here plays the role of a
 * protocol/version domain-separation label (the same pattern TLS 1.3's
 * HKDF-Expand-Label uses), NOT a per-user secret the way a password-hash
 * salt must be. Changing it would also silently break every
 * already-encrypted secret in this deployment (the derived KEK would
 * change), which is exactly the failure mode this hardening pass is
 * supposed to prevent, not cause.
 */

const VALID_ALGORITHMS = new Set(['AES-256-GCM', 'ChaCha20-Poly1305']);
const HEX_RE = /^[0-9a-fA-F]+$/;

function validateEncryptInputs(plaintext, alias, kekVersion, masterKeyHex, algorithm) {
  if (typeof plaintext !== 'string' || plaintext.length === 0) {
    throw new ValidationError('plaintext must be a non-empty string', 'CRYPTO_INVALID_PLAINTEXT');
  }
  if (typeof alias !== 'string' || alias.length === 0) {
    throw new ValidationError('alias must be a non-empty string', 'CRYPTO_INVALID_ALIAS');
  }
  if (!Number.isInteger(kekVersion) || kekVersion < 1) {
    throw new ValidationError('kekVersion must be a positive integer', 'CRYPTO_INVALID_KEK_VERSION');
  }
  if (typeof masterKeyHex !== 'string' || masterKeyHex.length !== 64 || !HEX_RE.test(masterKeyHex)) {
    throw new ValidationError('masterKeyHex must be a 64-character hex string (32 bytes)', 'CRYPTO_INVALID_MASTER_KEY');
  }
  if (algorithm && !VALID_ALGORITHMS.has(algorithm)) {
    throw new ValidationError(`algorithm must be one of: ${[...VALID_ALGORITHMS].join(', ')}`, 'CRYPTO_INVALID_ALGORITHM');
  }
}

function validateDecryptPayload(payload, masterKeyHex) {
  if (!payload || typeof payload !== 'object') {
    throw new ValidationError('payload must be an object', 'CRYPTO_INVALID_PAYLOAD');
  }
  const required = ['alias', 'kekVersion', 'encryptedDekHex', 'ivHex', 'authTagHex', 'ciphertextHex'];
  for (const field of required) {
    if (payload[field] === undefined || payload[field] === null) {
      throw new ValidationError(`payload.${field} is required`, 'CRYPTO_INVALID_PAYLOAD');
    }
  }
  if (payload.encryptedDekHex.split(':').length !== 3) {
    throw new ValidationError('payload.encryptedDekHex must be "iv:tag:ciphertext" (3 colon-separated hex parts)', 'CRYPTO_INVALID_PAYLOAD');
  }
  for (const field of ['ivHex', 'authTagHex', 'ciphertextHex']) {
    if (!HEX_RE.test(payload[field])) {
      throw new ValidationError(`payload.${field} must be valid hex`, 'CRYPTO_INVALID_PAYLOAD');
    }
  }
  if (typeof masterKeyHex !== 'string' || masterKeyHex.length !== 64 || !HEX_RE.test(masterKeyHex)) {
    throw new ValidationError('masterKeyHex must be a 64-character hex string (32 bytes)', 'CRYPTO_INVALID_MASTER_KEY');
  }
}

export function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function deriveKek(masterKeyHex, alias, version) {
  const info = Buffer.from(`KEK:${alias}:v${version}`, 'utf-8');
  const salt = Buffer.from('ISHV4_KEK_SALT_V1', 'utf-8');
  const derived = Buffer.from(
    crypto.hkdfSync('sha256', Buffer.from(masterKeyHex, 'hex'), salt, info, 32)
  );
  logEvent({
    action: 'CRYPTO_KEY_DERIVATION',
    status: 'SUCCESS',
    resourcePath: '/crypto/derive-kek',
    details: `alias=${alias} version=${version}`,
  });
  return derived;
}

export function envelopeEncrypt(plaintext, alias, kekVersion, masterKeyHex, algorithm = 'AES-256-GCM', aad, tenantId) {
  try {
    validateEncryptInputs(plaintext, alias, kekVersion, masterKeyHex, algorithm);
    if (tenantId !== undefined && (typeof tenantId !== 'string' || tenantId.length === 0 || tenantId.length > 128)) throw new ValidationError('tenantId must be a non-empty string when provided', 'CRYPTO_INVALID_TENANT');
    const start = performance.now();
  const kek = deriveKek(masterKeyHex, alias, kekVersion);

  const dek = crypto.randomBytes(32);
  const dekIv = crypto.randomBytes(12);
  const dekCipher = crypto.createCipheriv('aes-256-gcm', kek, dekIv);
  const encryptedDek = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
  const dekTag = dekCipher.getAuthTag();
  const encryptedDekHex = `${dekIv.toString('hex')}:${dekTag.toString('hex')}:${encryptedDek.toString('hex')}`;

  const iv = crypto.randomBytes(12);
  const cipher = algorithm === 'ChaCha20-Poly1305'
    ? crypto.createCipheriv('chacha20-poly1305', dek, iv, { authTagLength: 16 })
    : crypto.createCipheriv('aes-256-gcm', dek, iv);

  if (aad) cipher.setAAD(Buffer.from(aad, 'utf-8'));

  let ciphertext = cipher.update(plaintext, 'utf-8', 'hex');
  ciphertext += cipher.final('hex');
  const authTagHex = cipher.getAuthTag().toString('hex');

    return {
      algorithm,
      alias,
      kekVersion,
      encryptedDekHex,
      ivHex: iv.toString('hex'),
      authTagHex,
      ciphertextHex: ciphertext,
      aad: aad || null,
      ...(tenantId ? { tenantId } : {}),
      executionTimeMs: Number((performance.now() - start).toFixed(3)),
    };
  } catch (err) {
    logEvent({
      action: 'CRYPTO_ENCRYPT',
      status: 'FAIL',
      resourcePath: '/crypto/encrypt',
      errorCode: err?.code || 'CRYPTO_ENCRYPT_FAILED',
      details: 'encryption operation failed',
    });
    throw err;
  }
}

export function assertPayloadTenant(payload, tenantId) {
  if (!payload || typeof payload !== 'object') throw new ValidationError('payload is required', 'CRYPTO_INVALID_PAYLOAD');
  if (typeof tenantId !== 'string' || !tenantId) throw new ValidationError('tenantId is required', 'CRYPTO_INVALID_TENANT');
  if (!payload.tenantId || payload.tenantId !== tenantId) throw new ValidationError('Payload tenant does not match authenticated tenant', 'TENANT_CROSS_ACCESS_DENIED');
  return true;
}

export function envelopeDecrypt(payload, masterKeyHex) {
  const start = performance.now();
  try {
    validateDecryptPayload(payload, masterKeyHex);
    const kek = deriveKek(masterKeyHex, payload.alias, payload.kekVersion);

    const [dekIvHex, dekTagHex, dekCtHex] = payload.encryptedDekHex.split(':');
    const dekDecipher = crypto.createDecipheriv('aes-256-gcm', kek, Buffer.from(dekIvHex, 'hex'));
    dekDecipher.setAuthTag(Buffer.from(dekTagHex, 'hex'));
    const dek = Buffer.concat([dekDecipher.update(Buffer.from(dekCtHex, 'hex')), dekDecipher.final()]);

    const iv = Buffer.from(payload.ivHex, 'hex');
    const decipher = payload.algorithm === 'ChaCha20-Poly1305'
      ? crypto.createDecipheriv('chacha20-poly1305', dek, iv, { authTagLength: 16 })
      : crypto.createDecipheriv('aes-256-gcm', dek, iv);

    decipher.setAuthTag(Buffer.from(payload.authTagHex, 'hex'));
    if (payload.aad) decipher.setAAD(Buffer.from(payload.aad, 'utf-8'));

    let plaintext = decipher.update(payload.ciphertextHex, 'hex', 'utf-8');
    plaintext += decipher.final('utf-8'); // throws natively if auth tag doesn't match -> tamper detection

    const result = { plaintext, executionTimeMs: Number((performance.now() - start).toFixed(3)) };
    logEvent({
      action: 'CRYPTO_DECRYPT',
      status: 'SUCCESS',
      resourcePath: '/crypto/decrypt',
      details: `alias=${payload.alias} version=${payload.kekVersion}`,
    });
    return result;
  } catch (nativeErr) {
    if (nativeErr instanceof ValidationError) {
      logEvent({
        action: 'CRYPTO_DECRYPT',
        status: 'FAIL',
        resourcePath: '/crypto/decrypt',
        errorCode: nativeErr.code,
        details: 'invalid decrypt payload',
      });
      throw nativeErr;
    }
    // Node/OpenSSL's native exception is real and correct - tamper detection
    // itself is unchanged. We only wrap it so callers get a proper HTTP
    // status and machine-readable code instead of an unstructured native error.
    logEvent({
      action: 'CRYPTO_DECRYPT',
      status: 'FAIL',
      resourcePath: '/crypto/decrypt',
      errorCode: 'CRYPTO_DECRYPT_AUTH_FAILED',
      details: 'ciphertext authentication failed or wrong key/version',
    });
    throw new CryptoError(`Decryption failed - ciphertext may be tampered, or wrong key/version: ${nativeErr.message}`, 'CRYPTO_DECRYPT_AUTH_FAILED');
  }
}

// --- Ed25519 signatures (classical, NOT post-quantum) ---
export function generateEd25519KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
  };
}

export function signEd25519(message, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return crypto.sign(null, Buffer.from(message, 'utf-8'), key).toString('hex');
}

export function verifyEd25519(message, signatureHex, publicKeyPem) {
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    return crypto.verify(null, Buffer.from(message, 'utf-8'), key, Buffer.from(signatureHex, 'hex'));
  } catch {
    return false;
  }
}

// --- X25519 Diffie-Hellman key exchange (classical, NOT post-quantum) ---
export function performX25519Exchange() {
  const start = performance.now();
  const alice = crypto.generateKeyPairSync('x25519');
  const bob = crypto.generateKeyPairSync('x25519');

  const aliceShared = crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });
  const bobShared = crypto.diffieHellman({ privateKey: bob.privateKey, publicKey: alice.publicKey });

  const agree = aliceShared.equals(bobShared);
  const derivedKeyHex = crypto.createHash('sha256').update(aliceShared).digest('hex');

  return {
    algorithm: 'X25519 (classical elliptic-curve Diffie-Hellman)',
    alicePublicKeyDerHex: alice.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    bobPublicKeyDerHex: bob.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
    sharedSecretsAgree: agree,
    derivedKeyHex,
    executionTimeMs: Number((performance.now() - start).toFixed(3)),
  };
}
