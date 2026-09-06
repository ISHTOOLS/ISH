import crypto from 'node:crypto';

function keyFromEnv(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value.replace(/\\n/g, '\n');
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

export function issueSignedLicense({ order }) {
  if (!order || order.status !== 'PAID') throw new Error('Only PAID orders can receive a license');
  if (!order.hwid) throw new Error('HWID is required for license issuance');

  const now = new Date();
  const payload = {
    iss: process.env.ISH_LICENSE_ISSUER || 'ISH',
    jti: crypto.randomUUID(),
    customerId: order.customerId,
    planId: order.planId,
    hwid: order.hwid,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + order.durationDays * 86400000).toISOString(),
    orderId: order.id,
    paymentReference: order.reference
  };

  const encoded = b64url(JSON.stringify(payload));
  const privateKey = crypto.createPrivateKey(keyFromEnv('ISH_LICENSE_PRIVATE_KEY'));
  const signature = crypto.sign(null, Buffer.from(encoded), privateKey).toString('base64url');
  return `ISH-L1.${encoded}.${signature}`;
}

export function verifySignedLicense(token, publicKeyText = process.env.ISH_LICENSE_PUBLIC_KEY) {
  if (!publicKeyText) throw new Error('ISH_LICENSE_PUBLIC_KEY is required');
  const [prefix, encoded, signature] = String(token || '').split('.');
  if (prefix !== 'ISH-L1' || !encoded || !signature) return { valid: false, reason: 'Malformed license' };

  const publicKey = crypto.createPublicKey(publicKeyText.replace(/\\n/g, '\n'));
  const valid = crypto.verify(null, Buffer.from(encoded), publicKey, Buffer.from(signature, 'base64url'));
  if (!valid) return { valid: false, reason: 'Invalid signature' };

  let payload;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'Invalid payload' };
  }

  if (new Date(payload.expiresAt) <= new Date()) return { valid: false, reason: 'License expired', payload };
  return { valid: true, payload };
}
