const STATUSES = Object.freeze({
  CONFIRMED_SAFE: "CONFIRMED_SAFE",
  CONFIRMED_VULNERABLE: "CONFIRMED_VULNERABLE",
  MITIGATED: "MITIGATED",
  NOT_AFFECTED: "NOT_AFFECTED",
  UNKNOWN: "UNKNOWN",
  NOT_CONFIGURED: "NOT_CONFIGURED",
  UNAVAILABLE: "UNAVAILABLE"
});

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function normalizeAsset(asset) {
  return {
    id: nonEmptyString(asset?.id) ? asset.id : null,
    host: nonEmptyString(asset?.host) ? asset.host : null,
    service: nonEmptyString(asset?.service) ? asset.service : null,
    port: Number.isInteger(asset?.port) ? asset.port : null,
    product: nonEmptyString(asset?.product) ? asset.product : null,
    version: nonEmptyString(asset?.version) ? asset.version : null,
    evidence: Array.isArray(asset?.evidence) ? asset.evidence.filter(nonEmptyString) : []
  };
}

function validateProvider(provider, name) {
  if (!provider || typeof provider.search !== "function") {
    return { status: STATUSES.NOT_CONFIGURED, provider: name };
  }
  return null;
}

function severityScore(item) {
  const cvss = Number(item?.cvss);
  const epss = Number(item?.epss);
  const kev = item?.kev === true ? 1 : 0;
  const cvssScore = Number.isFinite(cvss) ? Math.max(0, Math.min(10, cvss)) / 10 : 0;
  const epssScore = Number.isFinite(epss) ? Math.max(0, Math.min(1, epss)) : 0;
  return Number((cvssScore * 0.65 + epssScore * 0.25 + kev * 0.10).toFixed(4));
}

function buildAttackPath(assets, findings) {
  const nodes = assets.map((asset) => ({ id: asset.id, type: "asset", label: asset.host || asset.id || "UNKNOWN" }));
  const edges = [];
  for (const finding of findings) {
    if (finding.asset_id && finding.status === STATUSES.CONFIRMED_VULNERABLE) {
      edges.push({ from: "external-entry", to: finding.asset_id, relation: "exposure" });
    }
  }
  return { nodes: [{ id: "external-entry", type: "origin", label: "External exposure" }, ...nodes], edges };
}

/**
 * Defensive, non-weaponized autonomous validation pipeline.
 *
 * Providers are dependency-injected so production connectors can supply real
 * data without embedding fake sources. Missing providers produce explicit
 * NOT_CONFIGURED/UNAVAILABLE/UNKNOWN states.
 *
 * The engine never generates, executes, modifies, or evades exploit payloads.
 */
export function createAutonomousSecurityValidation({ knowledgeProvider, assetProvider, auditSink } = {}) {
  const providerError = validateProvider(knowledgeProvider, "knowledge");
  const assetError = assetProvider && typeof assetProvider.discover === "function"
    ? null
    : { status: STATUSES.NOT_CONFIGURED, provider: "assets" };

  async function discover() {
    if (assetError) return { status: assetError.status, provider: assetError.provider, assets: [] };
    try {
      const assets = await assetProvider.discover();
      if (!Array.isArray(assets)) return { status: STATUSES.UNAVAILABLE, provider: "assets", assets: [] };
      return { status: STATUSES.CONFIRMED_SAFE, provider: "assets", assets: assets.map(normalizeAsset) };
    } catch (error) {
      return { status: STATUSES.UNAVAILABLE, provider: "assets", assets: [], error: error instanceof Error ? error.message : "ASSET_DISCOVERY_FAILED" };
    }
  }

  async function correlate(asset) {
    if (providerError) return { status: providerError.status, provider: providerError.provider, matches: [] };
    try {
      const query = [asset.product, asset.version, asset.service].filter(Boolean).join(" ");
      if (!query) return { status: STATUSES.UNKNOWN, provider: "knowledge", matches: [] };
      const matches = await knowledgeProvider.search({ query, asset });
      return { status: Array.isArray(matches) ? STATUSES.CONFIRMED_SAFE : STATUSES.UNAVAILABLE, provider: "knowledge", matches: Array.isArray(matches) ? matches : [] };
    } catch (error) {
      return { status: STATUSES.UNAVAILABLE, provider: "knowledge", matches: [], error: error instanceof Error ? error.message : "KNOWLEDGE_SEARCH_FAILED" };
    }
  }

  async function validate(asset, match) {
    if (!match || !nonEmptyString(match.cve)) return { status: STATUSES.UNKNOWN, reason: "NO_CVE_EVIDENCE" };
    if (match.affected === false) return { status: STATUSES.NOT_AFFECTED, cve: match.cve };
    if (match.mitigated === true) return { status: STATUSES.MITIGATED, cve: match.cve };
    if (match.confirmed_vulnerable === true && Array.isArray(match.evidence) && match.evidence.length > 0) {
      return { status: STATUSES.CONFIRMED_VULNERABLE, cve: match.cve, evidence: match.evidence.filter(nonEmptyString), score: severityScore(match) };
    }
    return { status: STATUSES.UNKNOWN, cve: match.cve, reason: "INSUFFICIENT_EVIDENCE" };
  }

  async function run() {
    const discovery = await discover();
    const findings = [];
    for (const asset of discovery.assets) {
      const correlation = await correlate(asset);
      for (const match of correlation.matches) {
        const result = await validate(asset, match);
        findings.push({ asset_id: asset.id, ...result });
      }
      if (correlation.matches.length === 0) {
        findings.push({ asset_id: asset.id, status: correlation.status === STATUSES.CONFIRMED_SAFE ? STATUSES.UNKNOWN : correlation.status });
      }
    }
    const attackPath = buildAttackPath(discovery.assets, findings);
    const result = {
      status: discovery.status,
      assets: discovery.assets,
      findings,
      attack_path: attackPath,
      capabilities: Object.freeze({ discovery: true, knowledge_correlation: !providerError, safe_validation: true, exploit_execution: false, evasion: false, autonomous_pivoting: false })
    };
    if (typeof auditSink === "function") await auditSink({ action: "autonomous-security-validation.run", outcome: "COMPLETED", summary: { assets: result.assets.length, findings: result.findings.length } });
    return result;
  }

  return Object.freeze({ discover, correlate, validate, run, statuses: STATUSES });
}

export { STATUSES };
