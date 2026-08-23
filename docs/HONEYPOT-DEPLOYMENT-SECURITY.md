# ISHv4 Honeypot Deployment Security Baseline

- Dedicated VLAN + dedicated firewall zone.
- Production/internal routes explicitly denied and logged.
- Dedicated public IP / static NAT for the honeypot.
- Management path restricted to an approved source IP or bastion/VPN.
- Honeypot management API never exposed directly to the Internet.
- Egress deny by default; allow only required DNS/NTP/updates to controlled destinations.
- Sensor telemetry should use TLS/mTLS to the ISHv4 collector where possible.
- Separate sensor credentials/keys; never reuse KMS root material.
- Preserve UTC timestamps and sensor identifiers.
- Rotate and protect telemetry storage; apply tenant isolation for multi-tenant collection.
- Validate NAT and firewall policy before assigning a public IP.
