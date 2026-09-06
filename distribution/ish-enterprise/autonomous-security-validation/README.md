# ISH Enterprise — Autonomous Security Validation Distribution

This directory is the distribution copy of the validated Autonomous Security Validation layer from `ismailozdemir01/ISH-Enterprise`.

## Source of truth

- Source repository: `ismailozdemir01/ISH-Enterprise`
- Integrated source commit: `4b90e782aedabf79221f3334b898605c540ec666`
- Distribution repository: `ISHTOOLS/ISH`

The distribution is additive. Existing ISH files are not replaced or deleted.

## Runtime contract

The module consumes real asset and knowledge providers through dependency injection. It never fabricates production assets, CVEs, telemetry, or evidence.

Unavailable configuration is reported explicitly as `NOT_CONFIGURED`, `UNAVAILABLE`, or `UNKNOWN`.

## Safety boundary

This distribution is defensive only. It does not generate or execute exploit payloads, implement AV/EDR evasion, or perform autonomous lateral movement/pivoting.

## Verification

Run from a Node.js 24+ environment:

```bash
node --test distribution/ish-enterprise/autonomous-security-validation/test.js
```
