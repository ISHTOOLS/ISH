import test from "node:test";
import assert from "node:assert/strict";
import { createAutonomousSecurityValidation, STATUSES } from "./index.js";

test("missing providers return explicit NOT_CONFIGURED states", async () => {
  const engine = createAutonomousSecurityValidation();
  const result = await engine.run();
  assert.equal(result.status, STATUSES.NOT_CONFIGURED);
  assert.deepEqual(result.assets, []);
  assert.equal(result.findings.length, 0);
  assert.equal(result.capabilities.exploit_execution, false);
  assert.equal(result.capabilities.evasion, false);
  assert.equal(result.capabilities.autonomous_pivoting, false);
});

test("real provider data is correlated without fabricating missing evidence", async () => {
  const engine = createAutonomousSecurityValidation({
    assetProvider: { discover: async () => [{ id: "srv-01", host: "10.0.0.10", service: "https", port: 443, product: "Example Server", version: "1.2" }] },
    knowledgeProvider: { search: async ({ query }) => [{ cve: "CVE-TEST-0001", affected: true, confirmed_vulnerable: true, evidence: [query], cvss: 9.1, epss: 0.8, kev: true }] },
  });
  const result = await engine.run();
  assert.equal(result.assets.length, 1);
  assert.equal(result.findings[0].status, STATUSES.CONFIRMED_VULNERABLE);
  assert.equal(result.findings[0].cve, "CVE-TEST-0001");
  assert.equal(result.attack_path.edges.length, 1);
});

test("insufficient evidence remains UNKNOWN", async () => {
  const engine = createAutonomousSecurityValidation({
    assetProvider: { discover: async () => [{ id: "srv-02", product: "Example", version: "unknown" }] },
    knowledgeProvider: { search: async () => [{ cve: "CVE-TEST-0002", affected: true, confirmed_vulnerable: false }] },
  });
  const result = await engine.run();
  assert.equal(result.findings[0].status, STATUSES.UNKNOWN);
});

test("audit sink receives a completed run summary", async () => {
  const events = [];
  const engine = createAutonomousSecurityValidation({
    assetProvider: { discover: async () => [] },
    knowledgeProvider: { search: async () => [] },
    auditSink: async (event) => events.push(event),
  });
  await engine.run();
  assert.equal(events.length, 1);
  assert.equal(events[0].action, "autonomous-security-validation.run");
  assert.equal(events[0].outcome, "COMPLETED");
});
