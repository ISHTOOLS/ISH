import { vault } from '../src/vault.js';
import { VaultService } from '../src/vault-service.js';
import { assertTenantAccess } from '../src/tenant-guard.js';
import { getRequestContext } from '../src/request-context.js';
import { ValidationError } from '../src/errors.js';

const vaultService = new VaultService(vault);
const MAX_PLAINTEXT_BYTES = 256 * 1024;
const MAX_ALIAS_LENGTH = 128;

function trustedTenant(tenantId) {
  const context = getRequestContext();
  return assertTenantAccess(tenantId, { resourcePath: '/api/ishlock' }) || context.tenantId;
}

function validateCommon(alias, plaintext) {
  if (typeof alias !== 'string' || alias.trim().length === 0 || alias.length > MAX_ALIAS_LENGTH) {
    throw new ValidationError('alias is invalid', 'ISHLOCK_INVALID_INPUT');
  }
  if (typeof plaintext !== 'string' || Buffer.byteLength(plaintext, 'utf8') > MAX_PLAINTEXT_BYTES) {
    throw new ValidationError('plaintext is invalid', 'ISHLOCK_INVALID_INPUT');
  }
}

export async function encryptForTenant({tenantId,alias,plaintext,aad=null}) {
  validateCommon(alias, plaintext);
  const trusted = trustedTenant(tenantId);
  const r=await vaultService.encryptSecret(alias,plaintext,'AES-256-GCM',aad,trusted,trusted);
  return {algorithm:r.algorithm,alias:r.alias,kekVersion:r.kekVersion,ivHex:r.ivHex,authTagHex:r.authTagHex,ciphertextHex:r.ciphertextHex,encryptedDekHex:r.encryptedDekHex,aad:r.aad};
}

export function decryptForTenant({payload,tenantId}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new ValidationError('payload is required', 'ISHLOCK_INVALID_INPUT');
  }
  const trusted = trustedTenant(tenantId);
  return vaultService.decryptPayload(payload, trusted, trusted);
}
