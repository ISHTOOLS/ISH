/**
 * Security profile presets. Not a new enforcement mechanism - this is a
 * convenience layer that documents and validates KNOWN GOOD combinations
 * of the real flags already enforced in server.js/config.js (STRICT_MODE,
 * REQUIRE_MTLS, DISABLE_FALLBACKS, TRUST_PROXY). It does not silently
 * change behavior; it tells the operator what env vars to actually set,
 * and validates that a running instance's config matches a named profile
 * (useful for a startup banner or a compliance check in CI).
 */

export const PROFILES = {
  dev: {
    description: 'Yerel geliştirme - hiçbir kısıtlama zorunlu değil',
    expected: { STRICT_MODE: false, REQUIRE_MTLS: false, DISABLE_FALLBACKS: false, TRUST_PROXY: false },
  },
  production: {
    description: 'Standart üretim - gerçek IAM zorunlu, fallback\'ler kapalı',
    expected: { STRICT_MODE: true, REQUIRE_MTLS: false, DISABLE_FALLBACKS: true, TRUST_PROXY: false },
  },
  'high-security': {
    description: 'Yüksek güvenlik / devlet-kurum profili - mTLS zorunlu, hiçbir fallback yok',
    expected: { STRICT_MODE: true, REQUIRE_MTLS: true, DISABLE_FALLBACKS: true, TRUST_PROXY: false },
  },
};

export function checkProfileCompliance(profileName, actualConfig) {
  const profile = PROFILES[profileName];
  if (!profile) throw new Error(`Unknown profile: "${profileName}". Valid: ${Object.keys(PROFILES).join(', ')}`);

  const mismatches = [];
  for (const [key, expectedValue] of Object.entries(profile.expected)) {
    if (actualConfig[key] !== expectedValue) {
      mismatches.push({ flag: key, expected: expectedValue, actual: actualConfig[key] });
    }
  }
  return { profile: profileName, compliant: mismatches.length === 0, mismatches };
}
