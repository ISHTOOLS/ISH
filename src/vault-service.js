import { assertTenantAccess } from './tenant-guard.js';
import { TenantError } from './errors.js';
export class VaultService {
  constructor(vaultEngine) { this.vault = vaultEngine; }
  assertTenant(reqTenantId, tenantId, resourcePath = 'vault') {
    const requested = String(reqTenantId || 'default');
    const target = String(tenantId || 'default');
    if (requested !== target) throw new TenantError('Tenant context mismatch', 'TENANT_CONTEXT_MISMATCH');
    return assertTenantAccess(requested, { resourcePath, allowMissingContext: true });
  }
  status() { return this.vault.getStatus(); }
  init(k, n) { return this.vault.init(k, n); }
  unseal(i, s, ip) { return this.vault.submitUnsealShare(i, s, ip); }
  seal(ip) { return this.vault.seal(ip); }
  async createKey(a, alg, t, rt) { this.assertTenant(rt,t,`/vault/keys/${a}`); return this.vault.createKey(a,alg,t); }
  listKeys(t,rt) { this.assertTenant(rt,t,'/vault/keys'); return this.vault.listKeys(t); }
  async rotateKey(a,t,rt) { this.assertTenant(rt,t,`/vault/keys/${a}`); return this.vault.rotateKey(a,t); }
  async revokeKey(a,r,t,rt) { this.assertTenant(rt,t,`/vault/keys/${a}`); return this.vault.revokeKey(a,r,t); }
  async setKeyExpiry(a,e,t,rt) { this.assertTenant(rt,t,`/vault/keys/${a}`); return this.vault.setKeyExpiry(a,e,t); }
  async encryptSecret(a,p,alg,aad,t,rt) { this.assertTenant(rt,t,`/vault/secrets/${a}`); return this.vault.encryptSecret(a,p,alg,aad,t); }
  decryptSecretById(id,t,rt) { this.assertTenant(rt,t,`/vault/secrets/${id}`); return this.vault.decryptSecretById(id,t); }
  decryptPayload(payload, tenantId, rt) { this.assertTenant(rt, tenantId, '/vault/secrets/inline'); return this.vault.decryptPayload(payload, tenantId); }
  listSecrets(t,rt) { this.assertTenant(rt,t,'/vault/secrets'); return this.vault.listSecrets(t); }
}
