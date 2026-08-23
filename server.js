import express from 'express';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

import { vault } from './src/vault.js';
import { recordAudit, getAuditLogs, verifyAuditChain } from './src/audit.js';
import { rateLimitMiddleware } from './src/anomaly-rate-limit.js';
import { contentFilterMiddleware, getFilterRules, updateFilterRules } from './src/content-filter.js';
import { signEd25519, verifyEd25519, generateEd25519KeyPair, performX25519Exchange } from './src/crypto-engine.js';
import { mlkemKeygen, mlkemEncaps, mlkemDecaps, mldsaKeygen, mldsaSign, mldsaVerify, hybridKeyExchange } from './src/pqc-bridge.js';
import { hsmListObjects, hsmGenerateKeyPair, hsmSign, hsmVerify } from './src/hsm-bridge.js';
import { createUser, authenticate, enrollMfa, confirmMfaEnrollment, listUsers, ROLE_PERMISSIONS, resolveSession, hasAnyAdmin } from './src/iam.js';
import { generateBase32Secret, otpauthUri } from './src/totp.js';
import { getWhitelist, updateWhitelist, ipWhitelistMiddleware } from './src/ip-whitelist.js';
import { requestContextMiddleware } from './src/request-context.js';
import { tenantGuard } from './src/tenant-guard.js';
import { VaultService } from './src/vault-service.js';
import { runSecurityScan } from './security-agent/index.js';
import { runSpywareDefender } from './security/spywareDefender.js';
import { encryptForTenant, decryptForTenant } from './services/kmsClient.js';
import { orchestrate } from './src/orchestrator.js';
import { assertTenantAccess } from './src/tenant-guard.js';
import { ingestThreatEvent, ingestBatch, listThreatEvents, getThreatProfile, listThreatProfiles, listCampaigns, listIocs, getThreatStats, getAttackMap } from './src/threat-intelligence.js';
import { ingestSensorEvent, ingestSensorBatch } from './src/honeypot-telemetry.js';
import { observeConnection } from './src/port-scan-detector.js';
import { getLocalFeed, setLocalFeed, importFeedFile } from './src/threat-feed.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
import { config } from './src/config.js';

const PORT = config.PORT;
const ADMIN_TOKEN = config.ADMIN_TOKEN || null;
const vaultService = new VaultService(vault);

const startTime = Date.now();
const metrics = {
  httpRequestsTotal: 0,
  httpRequestsByStatus: {},
  encryptOpsTotal: 0,
  decryptOpsTotal: 0,
  contentFilterBlocksTotal: 0,
  rateLimitBlocksTotal: 0,
  threatIntelEventsTotal: 0,
  threatIntelCriticalTotal: 0,
};

function clientIp(req) {
  if (config.TRUST_PROXY) {
    return (req.headers['x-forwarded-for']?.toString().split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
  }
  return req.socket.remoteAddress || 'unknown';
}

// Resolve the IP once per request, consistently, and cache it on req so
// every downstream consumer (rate limiter, whitelist, audit) agrees on
// the same value instead of each re-deriving it slightly differently.
// This runs FIRST, before body parsing or rate limiting, so an
// IP-blocked request is rejected as cheaply as possible.
app.use((req, res, next) => {
  req.ishv4ResolvedIp = clientIp(req);
  next();
});

app.use(ipWhitelistMiddleware((req, ip) => {
  recordAudit(req.actorId || 'anonymous', 'IP_WHITELIST_BLOCKED', req.originalUrl, 403, ip, 'IP not in whitelist');
}));

app.use(express.json({ limit: config.BODY_LIMIT }));
app.use(rateLimitMiddleware((ip, anomaly) => {
  metrics.rateLimitBlocksTotal++;
  recordAudit('system', 'RATE_LIMIT_ANOMALY', '/*', 429, ip, `z-score=${anomaly.zScore.toFixed(2)} observedRate=${anomaly.observedRate.toFixed(1)}/s baseline=${anomaly.baseline.toFixed(1)}/s`);
}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/security/ip-whitelist', requireAdmin, handle((req, res) => {
  res.json({ success: true, ...getWhitelist() });
}));

app.put('/api/security/ip-whitelist', requireAdmin, handle((req, res) => {
  const updated = updateWhitelist(req.body);
  recordAudit(req.actorId, 'IP_WHITELIST_UPDATED', '/security/ip-whitelist', 200, clientIp(req), JSON.stringify(updated));
  res.json({ success: true, ...updated });
}));

// Resolves the real IAM identity from a session token (Authorization:
// Bearer <sessionToken> from /api/iam/login), so audit records reflect
// who ACTUALLY performed an action instead of a hardcoded 'operator'
// string. This directly closes a gap THREAT-MODEL.md's own Repudiation
// section identified. Falls back to 'anonymous' if no valid session is
// presented - IAM is additive/optional, not yet mandatory on every route.
app.use((req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const session = token ? resolveSession(token) : null;
  req.actorId = session?.username || 'anonymous';
  req.userRole = session?.role || null;
  req.sessionTenantId = session?.tenantId || null;
  // Tenant resolution: an authenticated IAM session's assigned tenant
  // always wins (a user cannot simply claim a different tenant via
  // header). Only when there's NO session do we fall back to an
  // explicit X-Tenant-ID header, for pre-IAM/service-to-service access
  // patterns. Either way it defaults to "default" - single-tenant
  // deployments never need to think about this at all.
  req.tenantId = session?.tenantId || 'default';
  next();
});

// ISHLock API keys are an existing service-to-service authentication mechanism.
// For those routes only, a valid mapped API key may establish the tenant before
// request context is created; X-Tenant-ID remains untrusted and is checked by
// the existing tenant guard afterwards.
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/ishlock/')) return next();
  const { tenantId } = resolveIshLockApiKey(req);
  if (tenantId) req.tenantId = tenantId;
  next();
});

app.use(requestContextMiddleware);
app.use(tenantGuard);

app.use(contentFilterMiddleware((req, matchType, pattern) => {
  metrics.contentFilterBlocksTotal++;
  recordAudit(req.actorId || 'anonymous', 'CONTENT_FILTER_BLOCKED', req.originalUrl, 403, clientIp(req), `type=${matchType} pattern=${pattern}`);
}));

// REQUIRE_MTLS=true: reject any request that did NOT arrive through the
// mTLS listener (mtls/mtls-server.js sets req.mtlsClientCN only after a
// real TLS handshake with a CA-signed client cert succeeded). Health
// checks are exempt so orchestrators (Docker/k8s) can still probe
// liveness over plain HTTP.
app.use((req, res, next) => {
  if (config.REQUIRE_MTLS && !['/healthz','/health','/ready'].includes(req.path) && !req.mtlsClientCN) {
    return res.status(495).json({ error: 'REQUIRE_MTLS=true - this request must arrive through the mTLS listener with a valid client certificate' });
  }
  next();
});

// Real constant-time admin token check (only enforced if ADMIN_TOKEN env var is set).
function requireAdmin(req, res, next) {
  // STRICT_MODE=true: switch entirely to real per-user IAM authentication
  // (Authorization: Bearer <sessionToken> from /api/iam/login, role must
  // be "admin"). The shared ADMIN_TOKEN convenience is not used at all
  // in this mode - this is the real fix for "RBAC not systematically
  // enforced" (flagged independently by THREAT-MODEL.md and by ChatGPT's
  // review). We do NOT try to accept both mechanisms on the same
  // Authorization header, since that's structurally impossible (a
  // header can carry one token value, not two).
  if (config.STRICT_MODE) {
    if (req.userRole !== 'admin') {
      return res.status(403).json({ error: 'STRICT_MODE requires a real IAM admin session (Authorization: Bearer <sessionToken> from POST /api/iam/login as an admin-role user)' });
    }
    return next();
  }

  if (!ADMIN_TOKEN) {
    // DISABLE_FALLBACKS=true: the "no token configured -> open" dev
    // convenience is a real, named fallback. When explicitly disabled,
    // fail CLOSED instead - this is what makes the flag real rather
    // than decorative.
    if (config.DISABLE_FALLBACKS) {
      return res.status(503).json({ error: 'ADMIN_TOKEN not configured and DISABLE_FALLBACKS=true - admin routes fail closed, not open' });
    }
    return next(); // dev mode only, documented in README
  }
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(provided.padEnd(ADMIN_TOKEN.length, '\0'));
  const b = Buffer.from(ADMIN_TOKEN.padEnd(provided.length || ADMIN_TOKEN.length, '\0'));
  const ok = provided.length === ADMIN_TOKEN.length && crypto.timingSafeEqual(a, b);
  if (!ok) return res.status(401).json({ error: 'Invalid or missing admin token' });
  next();
}


function requireThreatIntelIngest(req, res, next) {
  if (!config.THREAT_INTEL_ENABLED) return res.status(503).json({ error: 'Threat Intelligence Fabric is disabled' });
  if (config.THREAT_INTEL_REQUIRE_MTLS_INGEST && !req.mtlsClientCN) return res.status(495).json({ error: 'Threat intelligence ingestion requires mTLS' });
  const expected = config.THREAT_INTEL_INGEST_TOKEN;
  if (!expected) return res.status(503).json({ error: 'THREAT_INTEL_INGEST_TOKEN is not configured; ingestion fails closed' });
  const provided = (req.headers.authorization || '').startsWith('Bearer ') ? req.headers.authorization.slice(7) : '';
  const a = Buffer.from(provided.padEnd(expected.length, '\0'));
  const b = Buffer.from(expected.padEnd(provided.length || expected.length, '\0'));
  if (provided.length !== expected.length || !crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'Invalid threat-intelligence ingest token' });
  next();
}

function safeClientError(err) {
  const production = config.NODE_ENV === 'production';
  if (!production) return err.message || 'Request failed';
  // In production only deliberately classified operational errors expose
  // their message. Plain/unexpected Error instances stay generic so paths,
  // dependency messages and other internal details cannot reach clients.
  return err.isOperational === true ? (err.message || 'Request failed') : 'Internal server error';
}

function handle(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (err) {
      if (err.notLeader) {
        return res.status(409).json({ error: 'This node is not the cluster leader', leaderId: err.leaderId });
      }
      const status = err.statusCode || 400;
      const body = { error: safeClientError(err) };
      if (err.code) body.code = err.code; // machine-readable code is safe; sensitive details stay server-side
      if (config.NODE_ENV === 'production' && err.isOperational !== true) {
        body.error = 'Internal server error';
      }
      res.status(status).json(body);
    }
  };
}

// ---------- Optional Raft-backed HA clustering ----------
// Enabled by setting CLUSTER_NODE_ID and CLUSTER_PEERS (comma-separated
// base URLs of the OTHER nodes, e.g. "http://localhost:4002,http://localhost:4003").
// See src/raft.js and README "Yüksek Erişilebilirlik (HA) Kümesi" for the
// full security design - the master key never crosses the network.
const CLUSTER_NODE_ID = config.CLUSTER_NODE_ID || null;
const CLUSTER_PEERS = (config.CLUSTER_PEERS || '').split(',').map((s) => s.trim()).filter(Boolean);

if (CLUSTER_NODE_ID) {
  const { createRaftNode } = await import('./src/raft.js');
  const raftNode = createRaftNode({
    nodeId: CLUSTER_NODE_ID,
    peerUrls: CLUSTER_PEERS,
    clusterSecret: config.CLUSTER_SECRET,
    electionMinMs: config.RAFT_ELECTION_MIN_MS,
    electionMaxMs: config.RAFT_ELECTION_MAX_MS,
    heartbeatMs: config.RAFT_HEARTBEAT_MS,
    onApply: (command) => vault.applyClusterCommand(command),
  });
  vault.attachRaft(raftNode);
  app.use(raftNode.router);
  console.log(`[cluster] node=${CLUSTER_NODE_ID} peers=${CLUSTER_PEERS.join(',') || '(none)'}`);
}

// ---------- Content filter (word/URL blocklist) ----------
app.get('/api/filter/rules', handle((req, res) => {
  res.json({ success: true, ...getFilterRules() });
}));

app.put('/api/filter/rules', requireAdmin, handle((req, res) => {
  const updated = updateFilterRules(req.body);
  recordAudit(req.actorId, 'FILTER_RULES_UPDATED', '/filter/rules', 200, clientIp(req), JSON.stringify(updated));
  res.json({ success: true, ...updated });
}));

// ---------- IAM / RBAC / MFA ----------
// Bootstrap exception: if NO admin exists yet anywhere in the system,
// allow creating the first admin user without authentication - otherwise
// STRICT_MODE creates an unsolvable chicken-and-egg problem (you'd need
// an admin session to create the first admin). The instant one admin
// exists, this exception closes and requireAdmin's normal rules apply.
function requireAdminUnlessBootstrapping(req, res, next) {
  if (req.body?.role === 'admin' && !hasAnyAdmin()) {
    recordAudit('bootstrap', 'IAM_BOOTSTRAP_ADMIN_CREATED', '/iam/users', 200, clientIp(req), `First admin user "${req.body.username}" created via bootstrap exception`);
    return next();
  }
  return requireAdmin(req, res, next);
}

app.post('/api/iam/users', requireAdminUnlessBootstrapping, handle(async (req, res) => {
  const { username, password, role, tenantId } = req.body;
  if (!username || !password || !role) throw new Error('username, password, role are required');
  const user = await createUser(username, password, role, tenantId || 'default');
  recordAudit(req.actorId, 'IAM_USER_CREATED', `/iam/users/${username}`, 200, clientIp(req), `role=${role} tenant=${tenantId || 'default'}`);
  res.json({ success: true, user });
}));

app.get('/api/iam/users', requireAdmin, handle((req, res) => {
  res.json({ success: true, users: listUsers(), roles: ROLE_PERMISSIONS });
}));

app.post('/api/iam/users/:username/mfa/enroll', handle((req, res) => {
  const base32Secret = generateBase32Secret();
  const { totpSecretHex } = enrollMfa(req.params.username);
  res.json({
    success: true,
    totpSecretHex,
    base32Secret,
    otpauthUri: otpauthUri(req.params.username, base32Secret),
    note: 'Scan otpauthUri as a QR code in any TOTP app (Google Authenticator, Authy), then POST the first code to /mfa/confirm',
  });
}));

app.post('/api/iam/users/:username/mfa/confirm', handle((req, res) => {
  const { totpCode, base32Secret } = req.body;
  const result = confirmMfaEnrollment(req.params.username, totpCode, base32Secret);
  recordAudit(req.actorId, 'IAM_MFA_ENROLLED', `/iam/users/${req.params.username}`, 200, clientIp(req), 'MFA enabled');
  res.json({ success: true, ...result });
}));

app.post('/api/iam/login', handle(async (req, res) => {
  const { username, password, totpCode } = req.body;
  try {
    const result = await authenticate(username, password, totpCode);
    recordAudit(username, 'IAM_LOGIN_SUCCESS', '/iam/login', 200, clientIp(req), `role=${result.role}`);
    res.json({ success: true, ...result });
  } catch (err) {
    recordAudit(username || 'unknown', 'IAM_LOGIN_FAILED', '/iam/login', 401, clientIp(req), err.message);
    throw err;
  }
}));

// ---------- Observability: health check + Prometheus metrics ----------
app.use((req, res, next) => {
  res.on('finish', () => {
    metrics.httpRequestsTotal++;
    metrics.httpRequestsByStatus[res.statusCode] = (metrics.httpRequestsByStatus[res.statusCode] || 0) + 1;
  });
  next();
});

app.get('/healthz', (req, res) => {
  const status = vaultService.status();
  // "healthy" means the process is responsive; sealed is a normal state,
  // not unhealthy - orchestrators should not restart a sealed-but-alive
  // node, an operator needs to unseal it.
  res.json({
    status: 'ok',
    uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
    vaultInitialized: status.initialized,
    vaultSealed: status.sealed,
    clustered: status.cluster !== null,
    clusterRole: status.cluster?.role ?? null,
  });
});

app.get('/health', (req, res) => {
  const status = vaultService.status();
  res.json({ status: 'ok', service: 'ishv4-real-kms', requestId: req.requestId, vaultInitialized: status.initialized, vaultSealed: status.sealed });
});

app.get('/ready', (req, res) => {
  const status = vaultService.status();
  const ready = status.initialized && !status.sealed;
  res.status(ready ? 200 : 503).json({ ready, vaultInitialized: status.initialized, vaultSealed: status.sealed });
});

function resolveIshLockApiKey(req) {
  const provided = String(req.headers['x-ishlock-api-key'] || '');
  let mapping = {}; try { mapping = JSON.parse(process.env.ISHLOCK_API_KEYS || '{}'); } catch { return { tenantId: null }; }
  for (const [candidate, tenantId] of Object.entries(mapping)) {
    const a=Buffer.from(provided), b=Buffer.from(candidate), n=Math.max(a.length,b.length);
    const aa=Buffer.alloc(n), bb=Buffer.alloc(n); a.copy(aa); b.copy(bb);
    if (a.length===b.length && crypto.timingSafeEqual(aa,bb)) return {tenantId: String(tenantId)};
  }
  recordAudit('ishlock','ISHLOCK_AUTH_FAILED','/ishlock',401,clientIp(req),'invalid API key'); return {tenantId:null};
}

function validateIshLockEncrypt(req) {
  const { alias, plaintext } = req.body || {};
  if (typeof alias !== 'string' || alias.trim() === '' || typeof plaintext !== 'string') {
    const err = new Error('Invalid ISHLOCK request');
    err.statusCode = 400; err.code = 'ISHLOCK_INVALID_REQUEST'; err.isOperational = true;
    throw err;
  }
}

function validateIshLockDecrypt(req) {
  const { payload } = req.body || {};
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    const err = new Error('Invalid ISHLOCK request');
    err.statusCode = 400; err.code = 'ISHLOCK_INVALID_REQUEST'; err.isOperational = true;
    throw err;
  }
}

app.post('/api/ishlock/encrypt', handle(orchestrate('ishlock.encrypt', async (req, res) => {
  const { tenantId } = resolveIshLockApiKey(req);
  if (!tenantId) return res.status(401).json({ error: 'Authentication required', code: 'ISHLOCK_AUTH_INVALID', requestId: req.requestId });
  const trustedTenant = assertTenantAccess(tenantId, { resourcePath: '/api/ishlock/encrypt' });
  const { alias, plaintext, aad } = req.body;
  const result = await encryptForTenant({ tenantId: trustedTenant, alias, plaintext, aad });
  recordAudit('ishlock', 'ISHLOCK_ENCRYPT', `/ishlock/encrypt/${alias}`, 200, clientIp(req), `algorithm=${result.algorithm}`, {tenantId:trustedTenant,userId:req.actorId || 'ishlock'});
  res.json({ success:true, requestId:req.requestId, ...result });
}, { requireTenant: true, validate: validateIshLockEncrypt })));

app.post('/api/ishlock/decrypt', handle(orchestrate('ishlock.decrypt', async (req, res) => {
  const { tenantId } = resolveIshLockApiKey(req);
  if (!tenantId) return res.status(401).json({ error: 'Authentication required', code: 'ISHLOCK_AUTH_INVALID', requestId: req.requestId });
  const trustedTenant = assertTenantAccess(tenantId, { resourcePath: '/api/ishlock/decrypt' });
  const { payload } = req.body;
  const result = decryptForTenant({ payload, tenantId: trustedTenant });
  recordAudit('ishlock','ISHLOCK_DECRYPT','/ishlock/decrypt',200,clientIp(req),'algorithm=authenticated-envelope',{tenantId:trustedTenant,userId:req.actorId || 'ishlock'});
  res.json({ success:true, requestId:req.requestId, ...result });
}, { requireTenant: true, validate: validateIshLockDecrypt })));

function validateSpywareScan(req) {
  const body = req.body || {};
  if (body.paths !== undefined && !Array.isArray(body.paths)) {
    const err = new Error('Invalid spyware scan request');
    err.statusCode = 400; err.code = 'SPYWARE_INVALID_INPUT'; err.isOperational = true;
    throw err;
  }
  if (Array.isArray(body.paths) && body.paths.length > 100) {
    const err = new Error('Too many file paths');
    err.statusCode = 400; err.code = 'SPYWARE_INVALID_INPUT'; err.isOperational = true;
    throw err;
  }
}

app.post('/api/security/spyware-scan', requireAdmin, handle(orchestrate('security.spyware-scan', async (req, res) => {
  const contextTenant = req.tenantId;
  const result = runSpywareDefender({ paths: req.body?.paths || [], tenantId: contextTenant });
  res.json({ success: true, requestId: req.requestId, ...result });
}, { requireTenant: true, validate: validateSpywareScan })));


// ---------- Threat Intelligence / Honeypot Telemetry ----------
app.post('/api/threat-intel/ingest', requireThreatIntelIngest, handle((req, res) => {
  const event = ingestThreatEvent(req.body, { tenantId: req.tenantId, source: req.body?.source || 'generic' });
  if (event.destinationPort != null) observeConnection(event);
  metrics.threatIntelEventsTotal++;
  if (event.severity === 'critical') metrics.threatIntelCriticalTotal++;
  recordAudit(req.actorId || 'sensor', 'THREAT_INTEL_EVENT_INGESTED', '/threat-intel/ingest', 202, clientIp(req), `source=${event.source} type=${event.eventType} score=${event.threatScore}`, { tenantId:req.tenantId });
  res.status(202).json({ success:true, event });
}));

app.post('/api/threat-intel/ingest/batch', requireThreatIntelIngest, handle((req, res) => {
  const events = ingestBatch(req.body?.events || req.body, { tenantId:req.tenantId, source:req.body?.source || 'generic' });
  for (const e of events) { if (e.destinationPort != null) observeConnection(e); metrics.threatIntelEventsTotal++; if (e.severity==='critical') metrics.threatIntelCriticalTotal++; }
  recordAudit(req.actorId || 'sensor', 'THREAT_INTEL_BATCH_INGESTED', '/threat-intel/ingest/batch', 202, clientIp(req), `count=${events.length}`, {tenantId:req.tenantId});
  res.status(202).json({ success:true, count:events.length, events });
}));

for (const source of ['cowrie','dionaea','suricata','zeek']) {
  app.post(`/api/threat-intel/ingest/${source}`, requireThreatIntelIngest, handle((req,res)=>{
    const event = ingestSensorEvent(req.body, source, {tenantId:req.tenantId});
    if (event.destinationPort != null) observeConnection(event);
    metrics.threatIntelEventsTotal++; if (event.severity==='critical') metrics.threatIntelCriticalTotal++;
    recordAudit(req.actorId || 'sensor', 'HONEYPOT_EVENT_INGESTED', `/threat-intel/ingest/${source}`, 202, clientIp(req), `source=${source} type=${event.eventType} score=${event.threatScore}`, {tenantId:req.tenantId});
    res.status(202).json({success:true,event});
  }));
}

app.get('/api/threat-intel/events', requireAdmin, handle((req,res)=>res.json({success:true,events:listThreatEvents({limit:req.query.limit,sourceIp:req.query.sourceIp,eventType:req.query.eventType,severity:req.query.severity,since:req.query.since})})));
app.get('/api/threat-intel/profiles', requireAdmin, handle((req,res)=>res.json({success:true,profiles:listThreatProfiles(req.query.limit)})));
app.get('/api/threat-intel/profiles/:ip', requireAdmin, handle((req,res)=>{const p=getThreatProfile(req.params.ip); if(!p) return res.status(404).json({error:'Threat profile not found'}); res.json({success:true,profile:p});}));
app.get('/api/threat-intel/campaigns', requireAdmin, handle((req,res)=>res.json({success:true,campaigns:listCampaigns(req.query.limit)})));
app.get('/api/threat-intel/iocs', requireAdmin, handle((req,res)=>res.json({success:true,iocs:listIocs(req.query.limit)})));
app.get('/api/threat-intel/stats', requireAdmin, handle((req,res)=>res.json({success:true,stats:getThreatStats()})));
app.get('/api/threat-intel/attack-map', requireAdmin, handle((req,res)=>res.json({success:true,points:getAttackMap({limit:Number(req.query.limit)||1000})})));
app.get('/api/threat-intel/local-feed', requireAdmin, handle((req,res)=>res.json({success:true,feed:getLocalFeed()})));
app.put('/api/threat-intel/local-feed', requireAdmin, handle((req,res)=>{const result=setLocalFeed(req.body?.entries || req.body, req.body?.source || 'operator-import'); recordAudit(req.actorId,'THREAT_FEED_UPDATED','/threat-intel/local-feed',200,clientIp(req),`count=${result.count}`); res.json({success:true,...result});}));

app.get('/metrics', (req, res) => {
  const s = vaultService.status();
  const lines = [
    '# HELP ishv4_http_requests_total Total HTTP requests received',
    '# TYPE ishv4_http_requests_total counter',
    `ishv4_http_requests_total ${metrics.httpRequestsTotal}`,
    '# HELP ishv4_http_requests_by_status HTTP requests by status code',
    '# TYPE ishv4_http_requests_by_status counter',
    ...Object.entries(metrics.httpRequestsByStatus).map(([code, count]) => `ishv4_http_requests_by_status{code="${code}"} ${count}`),
    '# HELP ishv4_vault_sealed Whether the vault is currently sealed (1=sealed, 0=unsealed)',
    '# TYPE ishv4_vault_sealed gauge',
    `ishv4_vault_sealed ${s.sealed ? 1 : 0}`,
    '# HELP ishv4_vault_active_keys Number of active KEK aliases',
    '# TYPE ishv4_vault_active_keys gauge',
    `ishv4_vault_active_keys ${s.activeKeysCount}`,
    '# HELP ishv4_uptime_seconds Process uptime in seconds',
    '# TYPE ishv4_uptime_seconds counter',
    `ishv4_uptime_seconds ${Math.floor((Date.now() - startTime) / 1000)}`,
    '# HELP ishv4_encrypt_ops_total Total successful encrypt operations',
    '# TYPE ishv4_encrypt_ops_total counter',
    `ishv4_encrypt_ops_total ${metrics.encryptOpsTotal}`,
    '# HELP ishv4_decrypt_ops_total Total successful decrypt operations',
    '# TYPE ishv4_decrypt_ops_total counter',
    `ishv4_decrypt_ops_total ${metrics.decryptOpsTotal}`,
    '# HELP ishv4_content_filter_blocks_total Requests blocked by word/URL content filter',
    '# TYPE ishv4_content_filter_blocks_total counter',
    `ishv4_content_filter_blocks_total ${metrics.contentFilterBlocksTotal}`,
    '# HELP ishv4_rate_limit_blocks_total Requests blocked by anomaly-based rate limiter',
    '# TYPE ishv4_rate_limit_blocks_total counter',
    `ishv4_rate_limit_blocks_total ${metrics.rateLimitBlocksTotal}`,
    '# HELP ishv4_threat_intel_events_total Threat intelligence events ingested',
    '# TYPE ishv4_threat_intel_events_total counter',
    `ishv4_threat_intel_events_total ${metrics.threatIntelEventsTotal}`,
    '# HELP ishv4_threat_intel_critical_total Critical threat intelligence events',
    '# TYPE ishv4_threat_intel_critical_total counter',
    `ishv4_threat_intel_critical_total ${metrics.threatIntelCriticalTotal}`,
  ];
  if (s.cluster) {
    lines.push(
      '# HELP ishv4_raft_is_leader Whether this node is the current Raft leader',
      '# TYPE ishv4_raft_is_leader gauge',
      `ishv4_raft_is_leader ${s.cluster.role === 'leader' ? 1 : 0}`,
      '# HELP ishv4_raft_term Current Raft term',
      '# TYPE ishv4_raft_term counter',
      `ishv4_raft_term ${s.cluster.currentTerm}`
    );
  }
  res.set('Content-Type', 'text/plain; version=0.0.4');
  res.send(lines.join('\n') + '\n');
});

import { listModules, getModuleHelp } from './src/module-help.js';

import { listModuleRegistry, isModuleEnabled, setModuleEnabled } from './src/module-registry.js';

// ---------- Module registry (super-admin: enable/disable optional, certification-incompatible modules) ----------
app.get('/api/admin/modules', requireAdmin, handle((req, res) => {
  res.json({ success: true, modules: listModuleRegistry() });
}));

app.put('/api/admin/modules/:moduleId', requireAdmin, handle((req, res) => {
  const { enabled } = req.body;
  const result = setModuleEnabled(req.params.moduleId, enabled);
  recordAudit(req.actorId, 'MODULE_TOGGLED', `/admin/modules/${req.params.moduleId}`, 200, clientIp(req), `enabled=${enabled}`);
  res.json({ success: true, ...result });
}));

// ---------- Runtime module documentation / help system ----------
app.get('/api/help', handle((req, res) => {
  res.json({ success: true, modules: listModules() });
}));

app.get('/api/help/:moduleName', handle((req, res) => {
  res.json({ success: true, ...getModuleHelp(req.params.moduleName) });
}));

import { PROFILES, checkProfileCompliance } from './src/security-profiles.js';

app.get('/api/admin/security-profile/:profileName', requireAdmin, handle((req, res) => {
  const result = checkProfileCompliance(req.params.profileName, config);
  res.json({ success: true, ...result, allProfiles: Object.keys(PROFILES) });
}));

import { createTenant, listTenants } from './src/tenant-manager.js';

// ---------- Multi-tenant management (super-admin) ----------
app.post('/api/admin/tenants', requireAdmin, handle((req, res) => {
  const { tenantId, displayName } = req.body;
  if (!tenantId) throw new Error('tenantId is required');
  const tenant = createTenant(tenantId, displayName);
  recordAudit(req.actorId, 'TENANT_CREATED', `/admin/tenants/${tenantId}`, 200, clientIp(req), displayName || tenantId);
  res.json({ success: true, tenant });
}));

app.get('/api/admin/tenants', requireAdmin, handle((req, res) => {
  res.json({ success: true, tenants: listTenants() });
}));

// ---------- Vault lifecycle ----------
app.get('/api/vault/status', handle((req, res) => {
  res.json({ success: true, ...vaultService.status() });
}));

app.post('/api/vault/init', handle(async (req, res) => {
  const thresholdK = Number(req.body.thresholdK ?? 3);
  const totalSharesN = Number(req.body.totalSharesN ?? 5);
  const result = await vaultService.init(thresholdK, totalSharesN);
  res.json({
    success: true,
    warning: 'Save these shares now. The server does NOT store them. Losing more than (N-K) shares makes all vault data permanently unrecoverable.',
    ...result,
  });
}));

app.post('/api/vault/unseal', handle((req, res) => {
  const { shareIndex, shareHex } = req.body;
  if (!Number.isInteger(shareIndex) || typeof shareHex !== 'string') {
    throw new Error('shareIndex (number) and shareHex (string) are required');
  }
  const result = vaultService.unseal(shareIndex, shareHex, clientIp(req));
  res.json({ success: true, ...result });
}));

app.post('/api/vault/seal', requireAdmin, handle((req, res) => {
  vaultService.seal(clientIp(req));
  res.json({ success: true, message: 'Vault sealed. Master key wiped from process memory.' });
}));

// ---------- KMS key management ----------
app.post('/api/kms/keys', requireAdmin, handle(orchestrate('kms.keys.create', async (req, res) => {
  const { alias, algorithm } = req.body;
  if (!alias) throw new Error('alias is required');
  const key = await vaultService.createKey(alias, algorithm, req.tenantId, req.tenantId);
  recordAudit(req.actorId, 'KEY_CREATED', `/kms/keys/${alias}`, 200, clientIp(req), `algorithm=${key.algorithm}`);
  res.json({ success: true, key });
}, { requireTenant: true })));

app.get('/api/kms/keys', handle(orchestrate('kms.keys.list', (req, res) => {
  res.json({ success: true, keys: vaultService.listKeys(req.tenantId, req.tenantId) });
}, { requireTenant: true })));

app.post('/api/kms/keys/:alias/rotate', requireAdmin, handle(orchestrate('kms.keys.rotate', async (req, res) => {
  const key = await vaultService.rotateKey(req.params.alias, req.tenantId, req.tenantId);
  recordAudit(req.actorId, 'KEY_ROTATED', `/kms/keys/${req.params.alias}`, 200, clientIp(req), `new version=${key.version}`);
  res.json({ success: true, key });
}, { requireTenant: true })));

app.post('/api/kms/keys/:alias/revoke', requireAdmin, handle(orchestrate('kms.keys.revoke', async (req, res) => {
  const key = await vaultService.revokeKey(req.params.alias, req.body?.reason, req.tenantId, req.tenantId);
  recordAudit(req.actorId, 'KEY_REVOKED', `/kms/keys/${req.params.alias}`, 200, clientIp(req), req.body?.reason || '(sebep belirtilmedi)');
  res.json({ success: true, key });
}, { requireTenant: true })));

app.put('/api/kms/keys/:alias/expiry', requireAdmin, handle(orchestrate('kms.keys.expiry', async (req, res) => {
  const key = await vaultService.setKeyExpiry(req.params.alias, req.body?.expiresAt ?? null, req.tenantId, req.tenantId);
  recordAudit(req.actorId, 'KEY_EXPIRY_SET', `/kms/keys/${req.params.alias}`, 200, clientIp(req), `expiresAt=${req.body?.expiresAt}`);
  res.json({ success: true, key });
}, { requireTenant: true })));

// ---------- Encrypt / Decrypt ----------
app.post('/api/kms/encrypt', handle(orchestrate('kms.encrypt', async (req, res) => {
  const { alias, plaintext, algorithm, aad } = req.body;
  if (!alias || typeof plaintext !== 'string') throw new Error('alias and plaintext are required');
  const result = await vaultService.encryptSecret(alias, plaintext, algorithm, aad, req.tenantId, req.tenantId);
  metrics.encryptOpsTotal++;
  recordAudit(req.actorId, 'ENCRYPT', `/kms/encrypt/${alias}`, 200, clientIp(req), `${plaintext.length} bytes, ${result.algorithm}, id=${result.id}`);
  res.json({ success: true, ...result });
}, { requireTenant: true })));

app.post('/api/kms/decrypt', handle(orchestrate('kms.decrypt', (req, res) => {
  const { id, payload } = req.body;
  let result;
  if (id) {
    result = vaultService.decryptSecretById(id, req.tenantId, req.tenantId);
  } else if (payload) {
    result = vaultService.decryptPayload(payload, req.tenantId, req.tenantId);
  } else {
    throw new Error('Provide either { id } of a stored secret, or a full { payload } to decrypt directly');
  }
  metrics.decryptOpsTotal++;
  recordAudit(req.actorId, 'DECRYPT', id ? `/kms/decrypt/${id}` : '/kms/decrypt/inline', 200, clientIp(req), 'success');
  res.json({ success: true, ...result });
}, { requireTenant: true })));

app.get('/api/kms/secrets', handle(orchestrate('kms.secrets.list', (req, res) => {
  res.json({ success: true, secrets: vaultService.listSecrets(req.tenantId, req.tenantId) });
}, { requireTenant: true })));

// ---------- Ed25519 signatures (classical - explicitly NOT labeled post-quantum) ----------
app.post('/api/crypto/ed25519/sign', handle((req, res) => {
  const { message } = req.body;
  if (!message) throw new Error('message is required');
  const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
  const signatureHex = signEd25519(message, privateKeyPem);
  res.json({ success: true, algorithm: 'Ed25519 (classical, not post-quantum)', publicKeyPem, signatureHex });
}));

app.post('/api/crypto/ed25519/verify', handle((req, res) => {
  const { message, signatureHex, publicKeyPem } = req.body;
  const verified = verifyEd25519(message, signatureHex, publicKeyPem);
  res.json({ success: true, verified });
}));

// ---------- X25519 key exchange (classical - explicitly NOT labeled post-quantum) ----------
app.post('/api/crypto/x25519/exchange', handle((req, res) => {
  res.json({ success: true, ...performX25519Exchange() });
}));

// ---------- Real Post-Quantum Cryptography (liboqs / NIST FIPS 203 & 204) ----------
app.post('/api/pqc/mlkem/keygen', handle((req, res) => {
  res.json({ success: true, ...mlkemKeygen() });
}));

app.post('/api/pqc/mlkem/encaps', handle((req, res) => {
  const { publicKeyHex } = req.body;
  if (!publicKeyHex) throw new Error('publicKeyHex is required');
  res.json({ success: true, ...mlkemEncaps(publicKeyHex) });
}));

app.post('/api/pqc/mlkem/decaps', handle((req, res) => {
  const { secretKeyHex, ciphertextHex } = req.body;
  if (!secretKeyHex || !ciphertextHex) throw new Error('secretKeyHex and ciphertextHex are required');
  res.json({ success: true, ...mlkemDecaps(secretKeyHex, ciphertextHex) });
}));

app.post('/api/pqc/mldsa/keygen', handle((req, res) => {
  res.json({ success: true, ...mldsaKeygen() });
}));

app.post('/api/pqc/mldsa/sign', handle((req, res) => {
  const { secretKeyHex, message } = req.body;
  if (!secretKeyHex || !message) throw new Error('secretKeyHex and message are required');
  res.json({ success: true, ...mldsaSign(secretKeyHex, message) });
}));

app.post('/api/pqc/mldsa/verify', handle((req, res) => {
  const { publicKeyHex, message, signatureHex } = req.body;
  if (!publicKeyHex || !message || !signatureHex) throw new Error('publicKeyHex, message and signatureHex are required');
  res.json({ success: true, ...mldsaVerify(publicKeyHex, message, signatureHex) });
}));

app.post('/api/pqc/hybrid-exchange', handle((req, res) => {
  const result = hybridKeyExchange();
  recordAudit(req.actorId, 'PQC_HYBRID_EXCHANGE', '/pqc/hybrid-exchange', 200, clientIp(req), result.pqcAlgorithm);
  res.json({ success: true, ...result });
}));

// ---------- Real HSM / PKCS#11 (SoftHSM2 by default, swap module path for real hardware) ----------
app.get('/api/hsm/objects', handle((req, res) => {
  res.json({ success: true, ...hsmListObjects() });
}));

app.post('/api/hsm/keys', requireAdmin, handle((req, res) => {
  const { keyId, label, curve } = req.body;
  if (!keyId || !label) throw new Error('keyId and label are required');
  const result = hsmGenerateKeyPair(keyId, label, curve);
  recordAudit(req.actorId, 'HSM_KEY_GENERATED', `/hsm/keys/${keyId}`, 200, clientIp(req), label);
  res.json(result);
}));

app.post('/api/hsm/sign', handle((req, res) => {
  const { keyId, message } = req.body;
  if (!keyId || !message) throw new Error('keyId and message are required');
  const result = hsmSign(keyId, message);
  recordAudit(req.actorId, 'HSM_SIGN', `/hsm/sign/${keyId}`, 200, clientIp(req), 'signed via PKCS#11');
  res.json(result);
}));

app.post('/api/hsm/verify', handle((req, res) => {
  const { keyId, message, signatureHex } = req.body;
  if (!keyId || !message || !signatureHex) throw new Error('keyId, message and signatureHex are required');
  res.json(hsmVerify(keyId, message, signatureHex));
}));

// --- SIEM export formats (CEF and LEEF are real, standardized syslog
// message formats understood by Splunk, IBM QRadar, Microsoft Sentinel,
// ArcSight, and Wazuh's log collector) ---

const CEF_SEVERITY_MAP = {
  VAULT_INIT: 8, VAULT_UNSEAL_SUCCESS: 6, VAULT_UNSEAL_FAILED: 9, VAULT_SEALED: 5,
  KEY_CREATED: 4, KEY_ROTATED: 4, ENCRYPT: 2, DECRYPT: 2,
  HSM_KEY_GENERATED: 5, HSM_SIGN: 3, PQC_HYBRID_EXCHANGE: 2,
};

function escapeCefValue(v) {
  return String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\n/g, '\\n');
}

// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
function toCef(entry) {
  const severity = CEF_SEVERITY_MAP[entry.action] ?? 3;
  const ext = [
    `rt=${new Date(entry.timestamp).getTime()}`,
    `suser=${escapeCefValue(entry.actorId)}`,
    `src=${escapeCefValue(entry.ipAddress)}`,
    `request=${escapeCefValue(entry.resourcePath)}`,
    `cs1Label=commitSeq`, `cs1=${entry.seq}`,
    `cs2Label=integrityHmac`, `cs2=${entry.currentHmac?.slice(0, 16)}`,
    `msg=${escapeCefValue(entry.details)}`,
  ].join(' ');
  return `CEF:0|ISHv4|RealKMS|1.0|${escapeCefValue(entry.action)}|${escapeCefValue(entry.action)}|${severity}|${ext}`;
}

// LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Key=Value pairs
function toLeef(entry) {
  const fields = [
    `devTime=${entry.timestamp}`,
    `usrName=${entry.actorId}`,
    `src=${entry.ipAddress}`,
    `resource=${entry.resourcePath}`,
    `sev=${CEF_SEVERITY_MAP[entry.action] ?? 3}`,
    `commitSeq=${entry.seq}`,
    `integrityHmac=${entry.currentHmac?.slice(0, 16)}`,
    `msg=${entry.details}`,
  ].join('\t');
  return `LEEF:2.0|ISHv4|RealKMS|1.0|${entry.action}|\t${fields}`;
}

app.get('/api/audit/export', handle((req, res) => {
  const format = (req.query.format || 'cef').toLowerCase();
  const logs = getAuditLogs(Number(req.query.limit) || 500);
  if (format === 'json') return res.json({ success: true, logs });

  const lines = logs.map(format === 'leef' ? toLeef : toCef);
  res.set('Content-Type', 'text/plain');
  res.send(lines.join('\n') + '\n');
}));

// ---------- Audit log ----------
app.get('/api/audit/logs', handle((req, res) => {
  res.json({ success: true, logs: getAuditLogs(200) });
}));

app.get('/api/audit/verify', handle((req, res) => {
  res.json({ success: true, ...verifyAuditChain() });
}));

// ---------- Global error handler (safety net) ----------
// handle() already catches errors within individual routes - this is a
// second layer for anything that slips past it (body-parser JSON syntax
// errors, errors thrown by middleware itself, synchronous throws outside
// an async route handler). Must be registered LAST, after all routes.
app.use((err, req, res, next) => {
  const status = err.statusCode || err.status || 500;
  const operational = err.isOperational === true;
  const body = { error: operational ? safeClientError(err) : 'Internal server error', requestId: req.requestId };
  if (err.code && operational) body.code = err.code;
  if (!operational) console.error('[unhandled error]', err);
  recordAudit(req.actorId || 'system', 'UNHANDLED_ERROR', req.originalUrl || 'unknown', status, req.ishv4ResolvedIp || 'unknown', operational ? (err.message || 'operational error') : 'internal error', {tenantId:req.tenantId, userId:req.actorId || 'system', errorCode:err.code || 'INTERNAL_ERROR'});
  res.status(status).json(body);
});

export { app };

let httpServer = null;
if (process.env.ISHV4_NO_LISTEN !== 'true') httpServer = app.listen(PORT, () => {
  console.log(`ISHv4-Real KMS listening on http://localhost:${PORT}`);
  console.log(vault.isInitialized() ? '[vault] initialized, sealed on boot (real behavior, no auto-unseal)' : '[vault] not yet initialized - POST /api/vault/init to begin');
});
async function gracefulShutdown(signal) { recordAudit('system','SERVICE_SHUTDOWN','/process',200,'local',`signal=${signal}`); if(httpServer) await new Promise(r=>httpServer.close(r)); }
process.on('SIGTERM',()=>gracefulShutdown('SIGTERM').finally(()=>process.exit(0)));
process.on('SIGINT',()=>gracefulShutdown('SIGINT').finally(()=>process.exit(0)));

// Optional real mTLS listener on a second port. Any client without a
// certificate signed by our CA is rejected at the TLS layer, before any
// application code runs. Enable with MTLS_PORT=4443 (or any port).
if (process.env.MTLS_PORT) {
  const { startMtlsServer } = await import('./mtls/mtls-server.js');
  startMtlsServer(app, Number(process.env.MTLS_PORT));
}
