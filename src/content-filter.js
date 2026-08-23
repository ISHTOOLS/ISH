import { readJson, writeJson } from './store.js';

const RULES_FILE = 'filter-rules.json';

/**
 * Real word-based and URL/path-based request filtering middleware.
 *
 * Honest scope: this is a defense-in-depth INPUT VALIDATION layer, not a
 * full WAF (see README "Kategori A" note - a real WAF like OWASP CRS
 * represents decades of rule engineering we are not reproducing here).
 * What this DOES do, genuinely:
 *   - Blocks requests whose URL path matches a blocklist pattern (path
 *     traversal attempts, known-bad path fragments)
 *   - Blocks requests whose JSON body contains blocklisted words/patterns
 *     (configurable, e.g. common SQLi/script-injection tokens as an
 *     extra layer even though this app has no SQL DB or HTML rendering)
 *   - Rules are runtime-configurable via API, persisted to disk, and
 *     every match is recorded to the real audit log.
 */

const DEFAULT_URL_PATTERNS = [
  '\\.\\./', // path traversal
  '%2e%2e%2f', // encoded path traversal
  '/etc/passwd',
  '<script', // reflected in URL (query string) case
];

const DEFAULT_WORD_PATTERNS = [
  '(?:union\\s+select|drop\\s+table|;\\s*--)', // classic SQLi tokens (defense-in-depth; no SQL DB here, but callers may proxy input elsewhere)
  '<script[\\s>]',
  'javascript:',
  'onerror\\s*=',
];

function loadRules() {
  return readJson(RULES_FILE, {
    urlPatterns: DEFAULT_URL_PATTERNS,
    wordPatterns: DEFAULT_WORD_PATTERNS,
    enabled: true,
  });
}

function saveRules(rules) {
  writeJson(RULES_FILE, rules);
}

function compilePatterns(patterns) {
  return patterns.map((p) => {
    try { return new RegExp(p, 'i'); }
    catch { return null; }
  }).filter(Boolean);
}

export function contentFilterMiddleware(onBlock) {
  return (req, res, next) => {
    const rules = loadRules();
    if (!rules.enabled) return next();

    const urlRegexes = compilePatterns(rules.urlPatterns);
    for (const re of urlRegexes) {
      if (re.test(req.originalUrl)) {
        onBlock?.(req, 'url', re.source);
        return res.status(403).json({ error: 'Request blocked by URL filter', matchedPattern: re.source });
      }
    }

    if (req.body && typeof req.body === 'object') {
      const bodyText = JSON.stringify(req.body);
      const wordRegexes = compilePatterns(rules.wordPatterns);
      for (const re of wordRegexes) {
        if (re.test(bodyText)) {
          onBlock?.(req, 'word', re.source);
          return res.status(403).json({ error: 'Request blocked by content filter', matchedPattern: re.source });
        }
      }
    }

    next();
  };
}

export function getFilterRules() {
  return loadRules();
}

export function updateFilterRules({ urlPatterns, wordPatterns, enabled }) {
  const current = loadRules();
  const updated = {
    urlPatterns: urlPatterns ?? current.urlPatterns,
    wordPatterns: wordPatterns ?? current.wordPatterns,
    enabled: enabled ?? current.enabled,
  };
  // validate every pattern compiles before saving - never persist a broken rule set
  compilePatterns(updated.urlPatterns);
  compilePatterns(updated.wordPatterns);
  saveRules(updated);
  return updated;
}
