import { z } from 'zod';

/**
 * Centralized, validated configuration. All environment variables are
 * parsed and validated ONCE at startup with Zod - if anything is
 * malformed (wrong type, invalid port, contradictory flags), the process
 * exits immediately with a clear error INSTEAD OF starting in a
 * partially-broken or silently-insecure state. This directly addresses
 * the "config dağınık" / "fail-fast startup" gap identified in review.
 */

const boolFromEnv = (defaultVal) =>
  z.preprocess((v) => (v === undefined ? defaultVal : v === 'true' || v === '1'), z.boolean());

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  NODE_ENV: z.string().default('development'),
  MTLS_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  ADMIN_TOKEN: z.string().min(16, 'ADMIN_TOKEN must be at least 16 characters if set').optional(),

  // Secure deployment mode flags - real, enforced (see below)
  STRICT_MODE: boolFromEnv(false),
  REQUIRE_MTLS: boolFromEnv(false),
  DISABLE_FALLBACKS: boolFromEnv(false),
  // TRUST_PROXY=false (default): X-Forwarded-For is IGNORED, the real
  // socket address is used for rate limiting / anomaly detection / audit
  // IP logging. This closes the spoofing gap THREAT-MODEL.md and two
  // independent reviews flagged - an attacker cannot forge their way
  // around per-IP limits by sending a fake header unless you explicitly
  // opt in (only correct if a real reverse proxy sits in front and
  // strips/overwrites client-supplied XFF headers itself).
  TRUST_PROXY: boolFromEnv(false),

  CLUSTER_NODE_ID: z.string().optional(),
  CLUSTER_PEERS: z.string().optional(),
  CLUSTER_SECRET: z.string().min(16, 'CLUSTER_SECRET must be at least 16 characters').optional(),
  ISHV4_DATA_DIR: z.string().default('data'),
  BODY_LIMIT: z.string().default('256kb'),
  AUDIT_MAX_BYTES: z.coerce.number().int().positive().default(10485760),
  SESSION_TTL_MS: z.coerce.number().int().positive().default(8 * 60 * 60 * 1000),

  SIEM_HOST: z.string().optional(),
  SIEM_PORT: z.coerce.number().int().min(1).max(65535).optional(),
  SIEM_PROTOCOL: z.enum(['udp', 'tcp']).default('udp'),

  PKCS11_MODULE_PATH: z.string().optional(),
  HSM_PIN: z.string().optional(),

  RAFT_ELECTION_MIN_MS: z.coerce.number().int().positive().default(1500),
  RAFT_ELECTION_MAX_MS: z.coerce.number().int().positive().default(3000),
  RAFT_HEARTBEAT_MS: z.coerce.number().int().positive().default(500),

  THREAT_INTEL_ENABLED: boolFromEnv(true),
  THREAT_INTEL_INGEST_TOKEN: z.string().min(16, 'THREAT_INTEL_INGEST_TOKEN must be at least 16 characters if set').optional(),
  THREAT_INTEL_MAX_EVENTS: z.coerce.number().int().positive().default(50000),
  THREAT_INTEL_MAX_PROFILES: z.coerce.number().int().positive().default(20000),
  THREAT_INTEL_REQUIRE_MTLS_INGEST: boolFromEnv(false),
});

function loadConfig() {
  const parsed = ConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    console.error('❌ Konfigürasyon doğrulaması BAŞARISIZ - sunucu başlatılmıyor:');
    for (const issue of parsed.error.issues) {
      console.error(`   - ${issue.path.join('.')}: ${issue.message}`);
    }
    process.exit(1); // fail-fast: never start in a possibly-broken state
  }

  const cfg = parsed.data;

  // Cross-field validation Zod's object schema alone can't express:
  const errors = [];
  const production = cfg.NODE_ENV === 'production';
  if (production && !cfg.STRICT_MODE) {
    errors.push('NODE_ENV=production gerektirir: STRICT_MODE=true (admin endpointleri fail-closed ve IAM ile korunmalı)');
  }
  if (production && !cfg.DISABLE_FALLBACKS) {
    errors.push('NODE_ENV=production gerektirir: DISABLE_FALLBACKS=true (geliştirme fallbackleri kapatılmalı)');
  }
  if (cfg.STRICT_MODE && !cfg.ADMIN_TOKEN) {
    errors.push('STRICT_MODE=true gerektirir: ADMIN_TOKEN ayarlanmalı (admin endpoint\'leri açık kalamaz)');
  }
  if (cfg.REQUIRE_MTLS && !cfg.MTLS_PORT) {
    errors.push('REQUIRE_MTLS=true gerektirir: MTLS_PORT ayarlanmalı');
  }
  if (cfg.CLUSTER_NODE_ID && !cfg.CLUSTER_PEERS) {
    errors.push('CLUSTER_NODE_ID ayarlandıysa CLUSTER_PEERS de ayarlanmalı (tek node\'luk küme anlamsız)');
  }
  if (cfg.THREAT_INTEL_REQUIRE_MTLS_INGEST && !cfg.REQUIRE_MTLS) {
    errors.push('THREAT_INTEL_REQUIRE_MTLS_INGEST=true gerektirir: REQUIRE_MTLS=true');
  }
  if (cfg.CLUSTER_NODE_ID && !cfg.CLUSTER_SECRET) {
    errors.push('CLUSTER_NODE_ID ayarlandıysa CLUSTER_SECRET de ayarlanmalı - imzasız Raft node çalıştırılamaz (node impersonation riski)');
  }
  if (errors.length > 0) {
    console.error('❌ Konfigürasyon çapraz-doğrulama BAŞARISIZ - sunucu başlatılmıyor:');
    for (const e of errors) console.error(`   - ${e}`);
    process.exit(1);
  }

  return cfg;
}

export const config = loadConfig();
