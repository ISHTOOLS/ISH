import { readJson, writeJson } from './store.js';

const REGISTRY_FILE = 'module-registry.json';

/**
 * Module registry: lets a super-admin enable/disable OPTIONAL modules at
 * runtime without redeploying code. This exists specifically to resolve
 * a real architectural tension: some requested features (code
 * obfuscation, HWID licensing, behavioral biometric tracking - see
 * commercial-extensions/) are fundamentally incompatible with a
 * transparent, auditable codebase suitable for government/FIPS-style
 * certification review. Making them toggleable, off-by-default modules
 * means:
 *   - The CORE codebase stays fully auditable at all times.
 *   - A deployment aimed at certification simply never enables these
 *     modules (and can even be built/shipped without the
 *     commercial-extensions/ directory at all).
 *   - A deployment aimed at commercial use can enable them explicitly,
 *     with the operator making an informed choice.
 *
 * This registry does NOT bypass core security (vault, PQC, HSM, IAM are
 * not "modules" here - they are the permanent core and cannot be
 * disabled). Only genuinely optional, non-core capabilities are
 * registered here.
 */

const KNOWN_MODULES = {
  'threat-intelligence-fabric': {
    description: 'Real telemetry normalization, IOC extraction, threat scoring, attacker profiles and campaign correlation',
    certificationCompatible: true,
  },
  'honeypot-telemetry': {
    description: 'Real T-Pot/Cowrie/Dionaea/Suricata/Zeek telemetry adapters',
    certificationCompatible: true,
  },

  'code-obfuscation': {
    description: 'Build-time JS obfuscation for commercial-extensions/ code',
    certificationCompatible: false,
  },
  'code-encryption-at-rest': {
    description: 'AES-256 encryption of module files on disk, decrypted at runtime',
    certificationCompatible: false,
  },
  'hwid-licensing': {
    description: 'Hardware-ID based license enforcement (commercial anti-piracy)',
    certificationCompatible: false,
  },
  'behavioral-analysis': {
    description: 'Mouse/typing/click pattern analysis for bot detection (requires user consent)',
    certificationCompatible: false,
    requiresConsent: true,
  },
  'subscription-billing': {
    description: 'API key quotas, usage metering, subscription tiers',
    certificationCompatible: false,
  },
};

function loadRegistry() {
  return readJson(REGISTRY_FILE, {
    // ALL optional modules are OFF by default. A government/certification
    // deployment can simply never touch this file and remains clean.
    enabled: {},
  });
}

export function listModuleRegistry() {
  const { enabled } = loadRegistry();
  return Object.entries(KNOWN_MODULES).map(([id, meta]) => ({
    id,
    ...meta,
    enabled: !!enabled[id],
  }));
}

export function isModuleEnabled(moduleId) {
  const { enabled } = loadRegistry();
  return !!enabled[moduleId];
}

export function setModuleEnabled(moduleId, enabled) {
  if (!KNOWN_MODULES[moduleId]) throw new Error(`Unknown module: "${moduleId}"`);
  const registry = loadRegistry();
  registry.enabled[moduleId] = !!enabled;
  writeJson(REGISTRY_FILE, registry);
  return { id: moduleId, enabled: !!enabled, ...KNOWN_MODULES[moduleId] };
}
