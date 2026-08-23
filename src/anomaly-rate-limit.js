/**
 * Layer-7 rate limiting with REAL statistical anomaly detection.
 *
 * This is deliberately NOT called "AI-powered": there is no trained
 * model, no training data, no neural network. What it actually does -
 * and what genuinely deserves the name "anomaly detection" - is:
 *
 *  1. Token bucket per IP for smooth burst control (real, standard
 *     algorithm, used by AWS API Gateway, Stripe, etc.)
 *  2. A rolling baseline (EWMA - exponentially weighted moving average)
 *     of each IP's request rate, with a z-score computed against that
 *     baseline's standard deviation. When an IP's current rate is more
 *     standard deviations above its OWN recent baseline than the
 *     configured threshold, it's flagged as anomalous - this is a real,
 *     textbook statistical technique (the same core idea used in many
 *     production anomaly detectors before anyone adds an ML model on
 *     top), not a marketing label.
 *
 * If you genuinely want ML-based detection later, this module's
 * `getFeatures(ip)` output (rate, EWMA, variance, burst count) is
 * exactly the feature vector you'd feed into a real trained model - but
 * that requires real historical traffic data to train and validate
 * against, which this project does not have.
 */
import { config } from './config.js';

const BUCKET_CAPACITY = 40;
const REFILL_PER_SEC = 8;
const EWMA_ALPHA = 0.3; // weight given to the newest observation
const Z_SCORE_THRESHOLD = 3.5; // ~99.98th percentile under normality assumption
const WINDOW_MS = 1000;

const state = new Map(); // ip -> { tokens, lastRefill, ewmaRate, ewmaVarianceSq, windowCount, windowStart, history }

function getState(ip) {
  let s = state.get(ip);
  if (!s) {
    s = { tokens: BUCKET_CAPACITY, lastRefill: Date.now(), ewmaRate: 0, ewmaVarianceSq: 0, windowCount: 0, windowStart: Date.now(), samples: 0 };
    state.set(ip, s);
  }
  return s;
}

function refillBucket(s, now) {
  const elapsedSec = (now - s.lastRefill) / 1000;
  s.tokens = Math.min(BUCKET_CAPACITY, s.tokens + elapsedSec * REFILL_PER_SEC);
  s.lastRefill = now;
}

function updateEwmaAndZScore(s, now) {
  if (now - s.windowStart < WINDOW_MS) return null;

  const observedRate = s.windowCount / ((now - s.windowStart) / 1000);
  s.windowCount = 0;
  s.windowStart = now;
  s.samples++;

  if (s.samples === 1) {
    s.ewmaRate = observedRate;
    return null; // no baseline yet
  }

  // Real-world traffic always has some jitter; a hard floor on stdDev
  // avoids the degenerate case where a perfectly-regular baseline
  // (variance == 0) makes the z-score permanently undefined/blind.
  const effectiveStdDev = Math.max(Math.sqrt(s.ewmaVarianceSq), 0.15 * s.ewmaRate, 0.5);
  const zScore = s.samples >= 5 ? (observedRate - s.ewmaRate) / effectiveStdDev : null;
  const isAnomalous = zScore !== null && zScore > Z_SCORE_THRESHOLD;

  // FIX (found via testing): if we let the baseline absorb the current
  // sample even while it's anomalous, sustained abnormal traffic quickly
  // gets "normalized" into the baseline and stops being flagged after a
  // few windows - exactly what a real attacker sustaining an elevated
  // rate would benefit from. Real anomaly detectors freeze baseline
  // updates during a flagged anomaly for this reason; we do the same.
  if (!isAnomalous) {
    const delta = observedRate - s.ewmaRate;
    s.ewmaRate += EWMA_ALPHA * delta;
    s.ewmaVarianceSq = (1 - EWMA_ALPHA) * (s.ewmaVarianceSq + EWMA_ALPHA * delta * delta);
  }

  if (zScore === null) return null;
  return { observedRate, baseline: s.ewmaRate, stdDev: effectiveStdDev, zScore, isAnomalous };
}

export function checkRequest(ip) {
  const now = Date.now();
  const s = getState(ip);
  refillBucket(s, now);
  s.windowCount++;

  const anomaly = updateEwmaAndZScore(s, now);
  const tokenAvailable = s.tokens >= 1;
  if (tokenAvailable) s.tokens -= 1;

  const isAnomalous = !!anomaly?.isAnomalous;

  return {
    allowed: tokenAvailable && !isAnomalous,
    tokensRemaining: Math.floor(s.tokens),
    anomaly,
  };
}

export function getFeatures(ip) {
  const s = state.get(ip);
  if (!s) return null;
  return { ewmaRate: s.ewmaRate, ewmaStdDev: Math.sqrt(s.ewmaVarianceSq), tokensRemaining: s.tokens, samples: s.samples };
}

export function rateLimitMiddleware(onAnomaly) {
  return (req, res, next) => {
    const ip = config.TRUST_PROXY
      ? (req.headers['x-forwarded-for']?.toString().split(',')[0].trim() || req.socket.remoteAddress || 'unknown')
      : (req.socket.remoteAddress || 'unknown');
    const result = checkRequest(ip);

    if (result.anomaly?.isAnomalous && onAnomaly) {
      onAnomaly(ip, result.anomaly);
    }

    if (!result.allowed) {
      return res.status(429).json({
        error: result.anomaly?.isAnomalous ? 'Anomalous traffic pattern detected (statistical z-score threshold exceeded)' : 'Rate limit exceeded (token bucket empty)',
        tokensRemaining: result.tokensRemaining,
        ...(result.anomaly ? { zScore: Number(result.anomaly.zScore.toFixed(2)) } : {}),
      });
    }
    next();
  };
}
