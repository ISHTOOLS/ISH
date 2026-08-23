import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

/**
 * Real PKCS#11 HSM integration.
 *
 * By default this points at a local SoftHSM2 token (a real, standards-
 * compliant software HSM used by the OpenSC/OpenSSL/HashiCorp Vault
 * ecosystems for development and CI). Because it speaks the actual
 * PKCS#11 protocol, swapping in a physical HSM or AWS CloudHSM / YubiHSM
 * requires changing ONLY the PKCS11_MODULE_PATH environment variable -
 * no application code changes. That is the entire point of PKCS#11: it's
 * a vendor-neutral standard.
 *
 * The private key is generated INSIDE the token and marked
 * "never extractable". It never exists in this process's memory, on
 * this process's heap, or in any core dump of this process - only the
 * HSM/token can perform operations with it. We verified this with
 * `pkcs11-tool --list-objects`, which reports:
 *   Access: sensitive, always sensitive, never extractable, local
 */

const MODULE_PATH = process.env.PKCS11_MODULE_PATH || '/usr/lib/softhsm/libsofthsm2.so';
const HSM_PIN = process.env.HSM_PIN || null;
const SOFTHSM2_CONF = process.env.SOFTHSM2_CONF || null;

function env() {
  const e = { ...process.env };
  if (SOFTHSM2_CONF) e.SOFTHSM2_CONF = SOFTHSM2_CONF;
  return e;
}

function assertReady() {
  if (!fs.existsSync(MODULE_PATH)) {
    throw new Error(
      `PKCS#11 module bulunamadi: ${MODULE_PATH}. SoftHSM2 icin: apt install softhsm2 opensc. ` +
      `Gercek donanim HSM icin PKCS11_MODULE_PATH'i uretici .so dosyasina isaret edin.`
    );
  }
  if (!HSM_PIN) {
    throw new Error('HSM_PIN ortam degiskeni ayarlanmamis.');
  }
}

function run(args) {
  return execFileSync('pkcs11-tool', ['--module', MODULE_PATH, ...args], {
    encoding: 'utf-8',
    env: env(),
    timeout: 15000,
  });
}

export function hsmListObjects() {
  assertReady();
  const out = run(['--login', '--pin', HSM_PIN, '--list-objects']);
  return { raw: out };
}

export function hsmGenerateKeyPair(keyId, label, curve = 'prime256v1') {
  assertReady();
  const out = run([
    '--login', '--pin', HSM_PIN,
    '--keypairgen', '--key-type', `EC:${curve}`,
    '--id', keyId, '--label', label,
  ]);
  return { success: true, keyId, label, curve, note: 'Private key generated INSIDE the HSM token, never extractable.', raw: out };
}

/**
 * Signs `message` using a key that lives only inside the HSM. We hash
 * client-side (standard practice - the raw ECDSA mechanism on most
 * PKCS#11 tokens, including SoftHSM2, expects a pre-computed digest,
 * not an arbitrary-length message), then send only the 32-byte digest
 * across to the token for the actual signing operation.
 */
export function hsmSign(keyId, message) {
  assertReady();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ishv4-hsm-'));
  const digestPath = path.join(tmpDir, 'digest.bin');
  const sigPath = path.join(tmpDir, 'sig.bin');
  try {
    const digest = crypto.createHash('sha256').update(message, 'utf-8').digest();
    fs.writeFileSync(digestPath, digest);

    run(['--login', '--pin', HSM_PIN, '--sign', '--id', keyId, '--mechanism', 'ECDSA', '--input-file', digestPath, '--output-file', sigPath]);
    const signature = fs.readFileSync(sigPath);

    return {
      success: true,
      keyId,
      digestHex: digest.toString('hex'),
      signatureHex: signature.toString('hex'),
      mechanism: 'ECDSA (raw, over client-computed SHA-256 digest)',
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

export function hsmVerify(keyId, message, signatureHex) {
  assertReady();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ishv4-hsm-'));
  const digestPath = path.join(tmpDir, 'digest.bin');
  const sigPath = path.join(tmpDir, 'sig.bin');
  try {
    const digest = crypto.createHash('sha256').update(message, 'utf-8').digest();
    fs.writeFileSync(digestPath, digest);
    fs.writeFileSync(sigPath, Buffer.from(signatureHex, 'hex'));

    // IMPORTANT (found by testing, not assumed): pkcs11-tool exits with
    // status 0 even when the signature is invalid - it only reports the
    // result in stdout text ("Signature is valid" vs "Invalid signature").
    // Relying on the exit code alone here would silently accept every
    // signature. We parse the actual text.
    const out = run(['--login', '--pin', HSM_PIN, '--verify', '--id', keyId, '--mechanism', 'ECDSA', '--input-file', digestPath, '--signature-file', sigPath]);
    if (/signature is valid/i.test(out)) return { success: true, verified: true };
    if (/invalid signature/i.test(out)) return { success: true, verified: false };
    throw new Error(`Unexpected pkcs11-tool output, cannot determine verification result: ${out}`);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}
