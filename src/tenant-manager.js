import { readJson, writeJson } from './store.js';

const TENANTS_FILE = 'tenants.json';

/**
 * Real tenant registry - persisted to disk (unlike the in-memory-only
 * stub that was proposed for integration), and actually consulted by
 * vault.js to enforce isolation (see requireTenantMatch there) rather
 * than existing as a standalone, unconnected lookup table.
 */

export function createTenant(tenantId, displayName) {
  if (!/^[a-zA-Z0-9_-]{2,64}$/.test(tenantId)) {
    throw new Error('tenantId must be 2-64 chars, alphanumeric/underscore/hyphen only');
  }
  const tenants = readJson(TENANTS_FILE, []);
  if (tenants.find((t) => t.tenantId === tenantId)) throw new Error(`Tenant "${tenantId}" already exists`);
  const record = { tenantId, displayName: displayName || tenantId, createdAt: new Date().toISOString() };
  tenants.push(record);
  writeJson(TENANTS_FILE, tenants);
  return record;
}

export function listTenants() {
  return readJson(TENANTS_FILE, []);
}

export function tenantExists(tenantId) {
  return readJson(TENANTS_FILE, []).some((t) => t.tenantId === tenantId);
}
