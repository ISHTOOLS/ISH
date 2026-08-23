# T-Pot Integration

T-Pot remains a separate honeypot platform. ISHv4 integrates with its telemetry instead of embedding the complete T-Pot stack into the KMS process.

Recommended path:
`T-Pot -> Cowrie/Dionaea/Suricata/other sensors -> JSON telemetry -> ISHv4 -> Threat Intelligence Fabric -> SIEM`

Endpoints:
- POST `/api/threat-intel/ingest`
- POST `/api/threat-intel/ingest/cowrie`
- POST `/api/threat-intel/ingest/dionaea`
- POST `/api/threat-intel/ingest/suricata`
- POST `/api/threat-intel/ingest/zeek`
- POST `/api/threat-intel/ingest/batch`
- GET `/api/threat-intel/events`
- GET `/api/threat-intel/profiles`
- GET `/api/threat-intel/profiles/:ip`
- GET `/api/threat-intel/campaigns`
- GET `/api/threat-intel/iocs`
- GET `/api/threat-intel/stats`
- GET `/api/threat-intel/attack-map`

Do not expose ingestion endpoints publicly without authentication/mTLS and network ACLs.
