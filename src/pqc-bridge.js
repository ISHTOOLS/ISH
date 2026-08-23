import { execFileSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BRIDGE_BIN = path.join(__dirname, '..', 'c_pqc', 'ishv4_pqc_bridge');

function assertBinaryExists() {
  if (!fs.existsSync(BRIDGE_BIN)) {
    throw new Error(
      'ishv4_pqc_bridge derlenmemis. Once "cd c_pqc && ./build.sh" calistirin. ' +
      'Bu asamayi atlayip sahte bir sonuc dondurmuyoruz.'
    );
  }
}

function runBridge(args) {
  assertBinaryExists();
  const out = execFileSync(BRIDGE_BIN, args, { encoding: 'utf-8', timeout: 15000 });
  const parsed = JSON.parse(out);
  if (!parsed.success) throw new Error(parsed.error || 'PQC bridge error');
  return parsed;
}

// --- Real ML-KEM-1024 (FIPS 203) ---
export function mlkemKeygen() {
  return runBridge(['kem-keygen']);
}
export function mlkemEncaps(publicKeyHex) {
  return runBridge(['kem-encaps', publicKeyHex]);
}
export function mlkemDecaps(secretKeyHex, ciphertextHex) {
  return runBridge(['kem-decaps', secretKeyHex, ciphertextHex]);
}

// --- Real ML-DSA-87 (FIPS 204) ---
export function mldsaKeygen() {
  return runBridge(['sig-keygen']);
}
export function mldsaSign(secretKeyHex, message) {
  return runBridge(['sig-sign', secretKeyHex, message]);
}
export function mldsaVerify(publicKeyHex, message, signatureHex) {
  return runBridge(['sig-verify', publicKeyHex, message, signatureHex]);
}

/**
 * Hybrid key exchange: real X25519 (classical) + real ML-KEM-1024 (post-quantum),
 * combined via HKDF. This is the actual "belt and suspenders" construction used
 * by real hybrid-PQC deployments (e.g. Cloudflare/Google's X25519Kyber768 in
 * TLS 1.3): an attacker must break BOTH the elliptic-curve problem AND the
 * lattice problem to recover the session key, not just one or the other.
 */
export function hybridKeyExchange() {
  // Classical side
  const alice = crypto.generateKeyPairSync('x25519');
  const bob = crypto.generateKeyPairSync('x25519');
  const classicalShared = crypto.diffieHellman({ privateKey: alice.privateKey, publicKey: bob.publicKey });

  // Post-quantum side (real liboqs ML-KEM-1024)
  const kemKeys = mlkemKeygen();
  const encapsResult = mlkemEncaps(kemKeys.publicKeyHex);
  const decapsResult = mlkemDecaps(kemKeys.secretKeyHex, encapsResult.ciphertextHex);

  if (encapsResult.sharedSecretHex !== decapsResult.sharedSecretHex) {
    throw new Error('PQC shared secret mismatch - this should never happen, aborting');
  }

  const combinedInput = Buffer.concat([
    classicalShared,
    Buffer.from(encapsResult.sharedSecretHex, 'hex'),
  ]);
  const finalKey = crypto.hkdfSync(
    'sha256',
    combinedInput,
    Buffer.from('ISHV4_HYBRID_SALT_V1'),
    Buffer.from('hybrid-x25519-mlkem1024-v1'),
    32
  );

  return {
    construction: 'Hybrid X25519 + ML-KEM-1024, combined via HKDF-SHA256',
    classicalAlgorithm: 'X25519 (classical elliptic-curve DH)',
    pqcAlgorithm: encapsResult.algorithm,
    pqcSharedSecretMatches: true,
    finalDerivedKeyHex: Buffer.from(finalKey).toString('hex'),
    note: 'Final key requires breaking BOTH X25519 (ECDLP) and ML-KEM-1024 (module-LWE) to recover.',
  };
}
