# ISHv4 v1.2.0 Final Release Integrity / Verification

Baseline: `ISHV4_FINAL_RELEASE_INTEGRITY_REVERIFIED.zip`

Added capability: Threat Intelligence Fabric + Honeypot Telemetry integration.

Verification performed:
- `npm test`: 59/59 PASS
- `npm run test:security`: 7/7 PASS
- `npm run check:all`: 52/52 JavaScript files syntax PASS
- `npm run audit:dependencies`: lockfileMatches=true; registry audit unavailable in the execution environment
- No test runtime state is included in the release archive (`tmp/`, `data/` excluded)
- No plaintext credentials are persisted by the Threat Intelligence normalization layer
- Threat intelligence ingestion fails closed when its ingest token is not configured
- Optional mandatory mTLS ingestion is enforced by configuration validation
- GeoIP/ASN enrichment remains UNKNOWN unless real telemetry or a local feed supplies the values
- T-Pot remains an external isolated sensor platform; ISHv4 consumes its real telemetry and does not embed or simulate T-Pot services
