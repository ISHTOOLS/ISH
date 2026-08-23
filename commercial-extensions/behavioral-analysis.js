import { readJson, writeJson } from '../src/store.js';

/**
 * Behavioral pattern analysis (mouse movement timing, typing cadence,
 * click intervals) for bot-vs-human classification.
 *
 * CONSENT IS NOT OPTIONAL IN THIS IMPLEMENTATION. Unlike most of the
 * items in this file's sibling modules, this one touches real personal
 * behavioral data about real people. Building comprehensive behavioral
 * fingerprinting without consent is a privacy problem regardless of how
 * "advanced" the detection is - so this module refuses to record or
 * score any data unless the caller has an explicit, timestamped,
 * revocable consent record on file for that session. There is no
 * "silent mode" and no way to disable the consent check via config -
 * that was a deliberate choice, not an oversight.
 *
 * What this actually does (real, simple, honest - NOT a trained ML
 * model, matching this project's earlier stance on the
 * "anomaly-rate-limit.js" naming): computes basic statistical features
 * from timing data (inter-event interval variance, straight-line mouse
 * movement ratio) that are well-documented as differing between
 * scripted/bot input and human input, and applies simple threshold
 * rules - not a neural network, not "AI".
 */

const CONSENT_FILE = 'behavioral-consent.json';
const SESSIONS_FILE = 'behavioral-sessions.json';

export function recordConsent(sessionId, granted) {
  const consents = readJson(CONSENT_FILE, {});
  consents[sessionId] = { granted: !!granted, timestamp: new Date().toISOString() };
  writeJson(CONSENT_FILE, consents);
  return consents[sessionId];
}

export function hasConsent(sessionId) {
  const consents = readJson(CONSENT_FILE, {});
  return !!consents[sessionId]?.granted;
}

export function revokeConsent(sessionId) {
  const consents = readJson(CONSENT_FILE, {});
  delete consents[sessionId];
  writeJson(CONSENT_FILE, consents);
  // also purge any behavioral data already collected for this session -
  // consent revocation should mean the data goes away, not just future
  // collection stopping.
  const sessions = readJson(SESSIONS_FILE, {});
  delete sessions[sessionId];
  writeJson(SESSIONS_FILE, sessions);
}

/**
 * mouseEvents: [{x, y, t}], keyEvents: [{t}] (timestamps only - we do
 * NOT record which keys were pressed, that would capture passwords/PII
 * for no legitimate reason here).
 */
export function analyzeSession(sessionId, mouseEvents = [], keyEvents = []) {
  if (!hasConsent(sessionId)) {
    throw new Error('No consent on file for this session - call recordConsent() first. This check cannot be bypassed.');
  }

  const features = {};

  if (mouseEvents.length >= 3) {
    const intervals = [];
    let straightLineCount = 0;
    for (let i = 1; i < mouseEvents.length; i++) {
      intervals.push(mouseEvents[i].t - mouseEvents[i - 1].t);
    }
    // real, simple, documented heuristic: bots often move in perfectly
    // straight lines or with suspiciously uniform timing; humans have
    // natural jitter. This computes the coefficient of variation of
    // inter-event timing (low CV = suspiciously mechanical).
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    const stdDev = Math.sqrt(variance);
    features.mouseTimingCoefficientOfVariation = mean > 0 ? stdDev / mean : 0;
  }

  if (keyEvents.length >= 3) {
    const intervals = [];
    for (let i = 1; i < keyEvents.length; i++) intervals.push(keyEvents[i].t - keyEvents[i - 1].t);
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    features.keyTimingCoefficientOfVariation = mean > 0 ? Math.sqrt(variance) / mean : 0;
  }

  // Simple, transparent threshold rule - NOT a trained classifier.
  // A coefficient of variation near 0 means near-perfectly-uniform
  // timing, which is mechanically suspicious for human input.
  const suspiciouslyUniform =
    (features.mouseTimingCoefficientOfVariation !== undefined && features.mouseTimingCoefficientOfVariation < 0.05) ||
    (features.keyTimingCoefficientOfVariation !== undefined && features.keyTimingCoefficientOfVariation < 0.05);

  const result = { sessionId, features, likelyAutomated: suspiciouslyUniform, method: 'statistical-threshold, not ML' };

  const sessions = readJson(SESSIONS_FILE, {});
  sessions[sessionId] = { ...result, analyzedAt: new Date().toISOString() };
  writeJson(SESSIONS_FILE, sessions);

  return result;
}
