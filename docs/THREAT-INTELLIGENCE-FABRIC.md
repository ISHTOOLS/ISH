# ISHv4 Threat Intelligence Fabric

Real observed telemetry is normalized into threat intelligence. No simulated attacks are generated.

Internet-facing honeypots/sensors -> isolated VLAN/firewall zone -> T-Pot/Cowrie/Dionaea/Suricata/Zeek telemetry -> ISHv4 adapters -> normalization -> IOC extraction -> threat scoring -> attacker profiles -> campaign correlation -> audit/SIEM/dashboard.

Supported ingestion formats: generic, Cowrie, Dionaea, Suricata EVE-style, and Zeek conn/notice-style JSON.

Security requirements: dedicated VLAN/zone; default-deny internal routes; logged denied traffic; egress deny-by-default with only explicitly required destinations; restricted management source/bastion/VPN; dedicated public IP/NAT; no public ISHv4 management API; UTC timestamps; no plaintext credential storage; credential fingerprints only; payload fingerprints only; GeoIP/ASN is UNKNOWN when no real local data source is configured.

Threat scores are deterministic and explainable. They cover port scans, SSH brute force, RDP attacks, SMB probes, exploit attempts, malware payloads, web attacks and credential attacks, with repeat-activity and local-feed enrichment. No ML score is claimed unless a real model is configured.
