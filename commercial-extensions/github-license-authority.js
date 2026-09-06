import crypto from 'node:crypto';
import fs from 'node:fs';
import { issueSignedLicense } from './signed-license.js';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const privateKey = required('ISH_LICENSE_PRIVATE_KEY');
const customerId = required('LICENSE_CUSTOMER_ID');
const planId = required('LICENSE_PLAN_ID');
const hwid = required('LICENSE_HWID');
const durationDays = Number(required('LICENSE_DURATION_DAYS'));
const customerEmail = process.env.LICENSE_CUSTOMER_EMAIL?.trim() || null;
const orderId = process.env.LICENSE_ORDER_ID?.trim() || `github-${crypto.randomUUID()}`;
const paymentReference = process.env.LICENSE_PAYMENT_REFERENCE?.trim() || null;

if (!Number.isInteger(durationDays) || durationDays <= 0) throw new Error('LICENSE_DURATION_DAYS must be a positive integer');

const keyObject = crypto.createPrivateKey(privateKey);
if (keyObject.asymmetricKeyType !== 'ed25519') throw new Error('ISH_LICENSE_PRIVATE_KEY must be an Ed25519 private key');

const now = Date.now();
const order = {
  id: orderId,
  customerId,
  customerEmail,
  planId,
  hwid,
  durationDays,
  reference: paymentReference,
  status: 'PAID',
  paidAt: new Date(now).toISOString(),
  createdAt: new Date(now).toISOString()
};

process.env.ISH_LICENSE_PRIVATE_KEY = privateKey;
const license = issueSignedLicense({ order });
if (!license?.token) throw new Error('License generation failed');

const output = process.env.LICENSE_OUTPUT_FILE || 'license.txt';
fs.writeFileSync(output, `${license.token}\n`, { mode: 0o600 });
console.log(JSON.stringify({ generated: true, output, customerId, planId, durationDays, orderId, paymentReference }, null, 2));
