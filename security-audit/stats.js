/**
 * Real statistics for timing-side-channel analysis. This is the actual
 * technique used in real timing-attack research (e.g., the methodology
 * behind tools like dudect): collect many high-resolution timing
 * samples under two conditions, then run a real two-sample statistical
 * test (Welch's t-test, which doesn't assume equal variance) to check
 * whether the timing difference between them is large enough to be
 * distinguishable from noise - i.e., whether an attacker measuring
 * response times could plausibly infer which condition occurred.
 *
 * A |t| statistic above ~4.5 is the conventional threshold used by
 * dudect-style constant-time testing tools, because it corresponds to
 * an extremely low false-positive probability even across many repeated
 * tests. We use the same threshold here rather than inventing our own.
 */

export function mean(samples) {
  return samples.reduce((a, b) => a + b, 0) / samples.length;
}

export function variance(samples, m = mean(samples)) {
  return samples.reduce((a, b) => a + (b - m) ** 2, 0) / (samples.length - 1);
}

export function welchTTest(samplesA, samplesB) {
  const meanA = mean(samplesA), meanB = mean(samplesB);
  const varA = variance(samplesA, meanA), varB = variance(samplesB, meanB);
  const nA = samplesA.length, nB = samplesB.length;

  const standardError = Math.sqrt(varA / nA + varB / nB);
  const tStatistic = (meanA - meanB) / standardError;

  // Welch–Satterthwaite degrees of freedom (reported for completeness;
  // we use the fixed |t|>4.5 threshold rather than a p-value lookup,
  // same convention dudect uses, valid for the sample sizes here).
  const df = (varA / nA + varB / nB) ** 2 / ((varA / nA) ** 2 / (nA - 1) + (varB / nB) ** 2 / (nB - 1));

  return {
    meanA, meanB, meanDiffNs: meanA - meanB,
    stdDevA: Math.sqrt(varA), stdDevB: Math.sqrt(varB),
    tStatistic, degreesOfFreedom: df,
    likelyDistinguishable: Math.abs(tStatistic) > 4.5,
  };
}

/** Removes extreme outliers (e.g. GC pauses, OS scheduling jitter) that
 * would otherwise dominate the variance and hide a real, small,
 * systematic timing difference. Trimming is itself a real, standard
 * technique in timing-analysis methodology (dudect does this too). */
export function trimOutliers(samples, trimFraction = 0.05) {
  const sorted = [...samples].sort((a, b) => a - b);
  const cut = Math.floor(sorted.length * trimFraction);
  return sorted.slice(cut, sorted.length - cut);
}
