/**
 * ISHv4 Threat Intelligence Fabric.
 * Real telemetry normalization, IOC extraction, threat scoring, attacker profiling,
 * campaign correlation and local reputation enrichment. No mock data is generated.
 * Unknown enrichment remains UNKNOWN unless a real local feed/database is configured.
 */
import crypto from 'node:crypto';
import { readJson, writeJson } from './store.js';
import { getLocalFeed } from './threat-feed.js';

const FILE = 'threat-intelligence.json';
const MAX_EVENTS = Number(process.env.THREAT_INTEL_MAX_EVENTS || 50000);
const MAX_PROFILES = Number(process.env.THREAT_INTEL_MAX_PROFILES || 20000);

const state = readJson(FILE, { events: [], profiles: {}, iocs: {}, campaigns: {}, stats: { total: 0, byType: {}, byCountry: {} } });
if (!Array.isArray(state.events)) state.events = [];
if (!state.profiles || typeof state.profiles !== 'object') state.profiles = {};
if (!state.iocs || typeof state.iocs !== 'object') state.iocs = {};
if (!state.campaigns || typeof state.campaigns !== 'object') state.campaigns = {};
if (!state.stats) state.stats = { total: 0, byType: {}, byCountry: {} };

function clean(v, max = 4096) { return String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max); }
function sha256(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
function validIp(ip) {
  const s = String(ip || '').trim();
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-f:]+$/i.test(s) && s.includes(':');
}
function now() { return new Date().toISOString(); }
function persist() { writeJson(FILE, state); }

const WEIGHTS = {
  port_scan: 10, credential_attack: 20, exploit_attempt: 30, malware_payload: 40,
  suspicious_protocol: 15, repeated_attack: 10, known_malicious: 30, rdp_attack: 25,
  ssh_bruteforce: 20, smb_probe: 20, web_exploit: 25, dns_abuse: 15,
};

function classify(input) {
  const s = `${input.eventType || ''} ${input.service || ''} ${input.protocol || ''} ${input.action || ''} ${input.message || ''}`.toLowerCase();
  if (/brute|credential|login|auth.*fail|password/.test(s)) return input.service === 'ssh' ? 'ssh_bruteforce' : 'credential_attack';
  if (/rdp/.test(s)) return 'rdp_attack';
  if (/smb|445/.test(s)) return 'smb_probe';
  if (/scan|probe|port/.test(s)) return 'port_scan';
  if (/malware|payload|shellcode|ransom/.test(s)) return 'malware_payload';
  if (/exploit|cve|injection|traversal|command execution/.test(s)) return 'exploit_attempt';
  if (/http.*attack|web.*exploit|sqlmap|nikto/.test(s)) return 'web_exploit';
  return clean(input.eventType || 'network_observation', 80);
}

function extractIocs(input) {
  const text = JSON.stringify(input);
  const ips = [...new Set((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(validIp))];
  const urls = [...new Set((text.match(/https?:\/\/[^\s"'<>]+/gi) || []).map(x => clean(x, 1024)))];
  const hashes = [...new Set(text.match(/\b[a-f0-9]{64}\b/gi) || [])];
  const domains = [...new Set((text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || []).filter(x => !x.includes('localhost')))];
  return { ips, urls, hashes, domains };
}

function normalize(input, meta = {}) {
  const sourceIp = input.sourceIp || input.srcIp || input.src_ip || input.ip || input.clientIp || meta.sourceIp || 'UNKNOWN';
  const eventType = classify(input);
  const iocs = extractIocs({ ...input, sourceIp });
  const payload = input.payload ?? input.raw ?? input.message ?? '';
  const localFeed = getLocalFeed();
  const feedHit = sourceIp !== 'UNKNOWN' ? localFeed.entries?.[sourceIp] : null;
  const payloadFingerprint = payload ? sha256(payload) : null;
  return {
    id: crypto.randomUUID(), timestamp: input.timestamp || now(), source: clean(input.source || meta.source || 'unknown', 64),
    sensor: clean(input.sensor || meta.sensor || 'unknown', 128), tenantId: clean(input.tenantId || meta.tenantId || 'default', 128),
    sourceIp: clean(sourceIp, 128), sourcePort: Number.isFinite(Number(input.sourcePort)) ? Number(input.sourcePort) : null,
    destinationIp: clean(input.destinationIp || input.dstIp || input.dst_ip || 'UNKNOWN', 128),
    destinationPort: Number.isFinite(Number(input.destinationPort || input.dstPort)) ? Number(input.destinationPort || input.dstPort) : null,
    protocol: clean(input.protocol || 'UNKNOWN', 32).toLowerCase(), service: clean(input.service || 'UNKNOWN', 64).toLowerCase(),
    eventType, action: clean(input.action || eventType, 128), message: clean(input.message || input.description || '', 2048),
    username: input.username ? clean(input.username, 128) : null, credentialFingerprint: input.password ? sha256(input.password) : (input.credentialFingerprint || null),
    payloadFingerprint, country: clean(input.country || 'UNKNOWN', 64), asn: clean(input.asn || 'UNKNOWN', 128), organization: clean(input.organization || 'UNKNOWN', 256),
    geo: { lat: input.lat ?? feedHit?.lat ?? null, lon: input.lon ?? feedHit?.lon ?? null, source: input.geoSource || (feedHit?.lat != null && feedHit?.lon != null ? 'local-feed' : 'UNKNOWN') },
    knownMalicious: input.knownMalicious === true || !!feedHit, reputation: feedHit ? { status:'KNOWN_MALICIOUS', source: localFeed.source || 'local-feed', entry: typeof feedHit === 'object' ? { ...feedHit } : true } : { status:'UNKNOWN', source: localFeed.source || 'NOT_CONFIGURED' }, iocs,
    rawReference: input.rawReference ? clean(input.rawReference, 512) : null,
  };
}

function scoreEvent(e) {
  let score = WEIGHTS[e.eventType] || 5;
  if (e.knownMalicious) score += WEIGHTS.known_malicious;
  if (e.payloadFingerprint) score += 5;
  if (e.username) score += 3;
  const recent = state.events.filter(x => x.sourceIp === e.sourceIp && Date.parse(x.timestamp) >= Date.now() - 15 * 60 * 1000).length;
  if (recent >= 4) score += WEIGHTS.repeated_attack;
  return Math.min(100, score);
}

function updateProfile(e, score) {
  if (!e.sourceIp || e.sourceIp === 'UNKNOWN') return null;
  let p = state.profiles[e.sourceIp];
  if (!p) {
    if (Object.keys(state.profiles).length >= MAX_PROFILES) {
      const oldest = Object.keys(state.profiles).sort((a,b) => Date.parse(state.profiles[a].lastSeen)-Date.parse(state.profiles[b].lastSeen))[0];
      delete state.profiles[oldest];
    }
    p = state.profiles[e.sourceIp] = { sourceIp: e.sourceIp, firstSeen: e.timestamp, lastSeen: e.timestamp, eventCount: 0, threatScore: 0, maxThreatScore: 0, services: {}, ports: {}, eventTypes: {}, countries: {}, fingerprints: [], usernames: [], iocs: { ips: [], urls: [], hashes: [], domains: [] } };
  }
  p.lastSeen = e.timestamp; p.eventCount++;
  p.threatScore = Math.min(100, Math.round((p.threatScore * 0.8) + (score * 0.2)));
  p.maxThreatScore = Math.max(p.maxThreatScore, score);
  for (const [k,v] of [['services',e.service],['ports',e.destinationPort],['eventTypes',e.eventType],['countries',e.country]]) if (v !== null && v !== 'UNKNOWN') p[k][v] = (p[k][v] || 0) + 1;
  if (e.payloadFingerprint && !p.fingerprints.includes(e.payloadFingerprint)) p.fingerprints.push(e.payloadFingerprint);
  if (e.username && !p.usernames.includes(e.username)) p.usernames.push(e.username);
  for (const type of Object.keys(p.iocs)) for (const v of e.iocs[type] || []) if (!p.iocs[type].includes(v)) p.iocs[type].push(v);
  return p;
}

function correlateCampaign(e) {
  const key = sha256([e.payloadFingerprint || '', e.service, e.destinationPort || '', e.protocol, e.eventType, e.action].join('|')).slice(0, 20);
  let c = state.campaigns[key];
  if (!c) c = state.campaigns[key] = { id: key, firstSeen: e.timestamp, lastSeen: e.timestamp, eventCount: 0, sourceIps: [], services: [], eventTypes: [], fingerprints: [] };
  c.lastSeen = e.timestamp; c.eventCount++;
  for (const [arr,val] of [['sourceIps',e.sourceIp],['services',e.service],['eventTypes',e.eventType],['fingerprints',e.payloadFingerprint]]) if (val && val !== 'UNKNOWN' && !c[arr].includes(val)) c[arr].push(val);
  return c;
}

export function ingestThreatEvent(input, meta = {}) {
  const event = normalize(input, meta);
  const score = scoreEvent(event);
  event.threatScore = score;
  event.severity = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 35 ? 'medium' : 'low';
  state.events.push(event);
  if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS);
  state.stats.total++;
  state.stats.byType[event.eventType] = (state.stats.byType[event.eventType] || 0) + 1;
  if (event.country !== 'UNKNOWN') state.stats.byCountry[event.country] = (state.stats.byCountry[event.country] || 0) + 1;
  for (const type of Object.keys(event.iocs)) for (const value of event.iocs[type]) state.iocs[`${type}:${value}`] = { type, value, firstSeen: state.iocs[`${type}:${value}`]?.firstSeen || event.timestamp, lastSeen: event.timestamp, count: (state.iocs[`${type}:${value}`]?.count || 0) + 1 };
  updateProfile(event, score); correlateCampaign(event); persist();
  return event;
}

export function ingestBatch(events, meta = {}) { if (!Array.isArray(events)) throw new Error('events must be an array'); return events.map(e => ingestThreatEvent(e, meta)); }
export function listThreatEvents({ limit=100, sourceIp, eventType, severity, since } = {}) {
  let out = state.events.slice().reverse();
  if (sourceIp) out = out.filter(e => e.sourceIp === sourceIp);
  if (eventType) out = out.filter(e => e.eventType === eventType);
  if (severity) out = out.filter(e => e.severity === severity);
  if (since) out = out.filter(e => Date.parse(e.timestamp) >= Date.parse(since));
  return out.slice(0, Math.min(1000, Math.max(1, Number(limit) || 100)));
}
export function getThreatProfile(sourceIp) { return state.profiles[sourceIp] || null; }
export function listThreatProfiles(limit=100) { return Object.values(state.profiles).sort((a,b)=>b.threatScore-a.threatScore).slice(0, Math.min(1000, Number(limit)||100)); }
export function listCampaigns(limit=100) { return Object.values(state.campaigns).sort((a,b)=>Date.parse(b.lastSeen)-Date.parse(a.lastSeen)).slice(0, Math.min(1000, Number(limit)||100)); }
export function listIocs(limit=500) { return Object.values(state.iocs).sort((a,b)=>b.count-a.count).slice(0, Math.min(2000, Number(limit)||500)); }
export function getThreatStats() { return { ...state.stats, profiles: Object.keys(state.profiles).length, campaigns: Object.keys(state.campaigns).length, iocs: Object.keys(state.iocs).length, retainedEvents: state.events.length }; }
export function getAttackMap({ limit=1000 } = {}) { return state.events.filter(e => e.geo?.lat !== null && e.geo?.lon !== null).slice(-limit).map(e => ({ id:e.id,timestamp:e.timestamp,sourceIp:e.sourceIp,country:e.country,asn:e.asn,lat:e.geo.lat,lon:e.geo.lon,threatScore:e.threatScore,severity:e.severity,eventType:e.eventType })); }
export function enrichWithLocalReputation(ip, feed = {}) { const hit = feed[ip]; return hit ? { ...hit, source: 'local-feed' } : { status:'UNKNOWN', source:'NOT_CONFIGURED' }; }
