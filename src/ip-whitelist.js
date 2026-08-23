import { readJson, writeJson } from './store.js';

const WHITELIST_FILE = 'ip-whitelist.json';

/**
 * Real IP whitelist enforcement. Two modes:
 *  - "strict": only listed IPs/CIDR ranges may access the API at all
 *  - "wildcard" (default): whitelist is advisory/unused unless populated;
 *    once ANY entry exists, enforcement begins automatically
 *
 * Supports both exact IPs and CIDR ranges (e.g. "10.0.0.0/24") using
 * real bitwise subnet math - not string prefix matching, which would be
 * wrong for CIDR boundaries that don't fall on dotted-decimal edges.
 */

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function ipInCidr(ip, cidr) {
  const [rangeIp, prefixStr] = cidr.split('/');
  const prefix = Number(prefixStr);
  const ipInt = ipToInt(ip);
  const rangeInt = ipToInt(rangeIp);
  if (ipInt === null || rangeInt === null || Number.isNaN(prefix)) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

function matches(ip, entry) {
  if (entry.includes('/')) return ipInCidr(ip, entry);
  return ip === entry;
}

function loadWhitelist() {
  return readJson(WHITELIST_FILE, { mode: 'wildcard', entries: [] });
}

export function getWhitelist() {
  return loadWhitelist();
}

export function updateWhitelist({ mode, entries }) {
  // validate every entry before saving - fail loudly, don't persist garbage
  for (const e of entries || []) {
    if (!e.includes('/') && ipToInt(e) === null) throw new Error(`Invalid IP or CIDR entry: "${e}"`);
    if (e.includes('/') && !ipInCidr('0.0.0.0', e) && ipToInt(e.split('/')[0]) === null) throw new Error(`Invalid CIDR entry: "${e}"`);
  }
  const updated = { mode: mode || 'wildcard', entries: entries ?? loadWhitelist().entries };
  writeJson(WHITELIST_FILE, updated);
  return updated;
}

export function ipWhitelistMiddleware(onBlock) {
  return (req, res, next) => {
    const { mode, entries } = loadWhitelist();
    // "wildcard" mode with an empty list = no enforcement (default,
    // backward-compatible). The instant entries exist, OR mode is
    // "strict", enforcement is real and active.
    if (mode === 'wildcard' && entries.length === 0) return next();

    const ip = req.ishv4ResolvedIp || req.socket.remoteAddress || 'unknown';
    const allowed = entries.some((e) => matches(ip, e));
    if (!allowed) {
      onBlock?.(req, ip);
      return res.status(403).json({ error: 'IP not in whitelist', mode });
    }
    next();
  };
}
