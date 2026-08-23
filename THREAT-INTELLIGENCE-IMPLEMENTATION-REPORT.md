# ISHv4 Threat Intelligence Fabric — Implementation Report

Baseline: `ISHV4_FINAL_RELEASE_INTEGRITY_REVERIFIED.zip`
Target release: ISHv4 1.2.0

## Implemented

- Real telemetry ingestion with fail-closed bearer token and optional mandatory mTLS.
- Generic, Cowrie, Dionaea, Suricata and Zeek adapters.
- Deterministic event classification and threat scoring.
- IOC extraction: IP, URL, domain and SHA-256 hash indicators.
- Credential fingerprinting; plaintext passwords are not persisted in normalized events.
- Payload fingerprinting rather than raw payload persistence.
- Attacker profiles with first/last seen, services, ports, event types, fingerprints and IOC sets.
- Campaign correlation using deterministic behavioral fingerprints.
- Local reputation feed with UNKNOWN/NOT_CONFIGURED semantics when absent.
- Vertical/horizontal/broad port-scan classification.
- Protected threat-intelligence APIs and attack-map data endpoint.
- Prometheus metrics for ingested and critical events.
- Deployment-security documentation for VLAN, firewall, NAT, egress and management isolation.
- Automated tests covering telemetry normalization, credential handling, Suricata/Cowrie adapters, scan detection and persistence.

## Explicit non-goals

- No fabricated attack traffic.
- No claim of live GeoIP/ASN enrichment without a real local data source.
- No embedded T-Pot services inside the KMS process. T-Pot remains an external isolated sensor platform.
- No automatic offensive action against source IPs.

## Verification

`npm test`: 59/59 PASS

`npm run test:security`: 7/7 PASS

`npm run check:all`: 52/52 JavaScript files pass syntax validation

`npm run audit:dependencies`: lockfile matches; npm registry audit was unavailable in the build environment.
