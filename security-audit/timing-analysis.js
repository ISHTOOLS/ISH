import { envelopeEncrypt, envelopeDecrypt } from '../src/crypto-engine.js';
import { welchTTest, trimOutliers } from './stats.js';
import crypto from 'crypto';

/**
 * Real timing-side-channel analysis against this project's own
 * cryptographic operations. This does NOT claim to be a "comprehensive
 * penetration test" - real pentesting requires broad expertise and
 * tooling well beyond one script. What this genuinely IS: a real,
 * dudect-style statistical timing analysis of the specific operations
 * this KMS performs, to check whether an attacker measuring response
 * latency could distinguish "valid" from "invalid" inputs - which is
 * exactly the class of bug that has caused real CVEs (e.g. padding-
 * oracle and MAC-timing vulnerabilities in other systems).
 */

const SAMPLES = 2000;
const WARMUP = 200;

function hrtimeNs(fn) {
  const start = process.hrtime.bigint();
  fn();
  const end = process.hrtime.bigint();
  return Number(end - start);
}

function collectInterleaved(fnA, fnB, count) {
  // Interleaving A/B measurements (rather than measuring all of A, then
  // all of B) avoids systematic drift - e.g. CPU frequency scaling or
  // cache warmth changing over the course of the run - from masquerading
  // as a timing difference between the two conditions.
  const samplesA = [], samplesB = [];
  for (let i = 0; i < count; i++) {
    samplesA.push(hrtimeNs(fnA));
    samplesB.push(hrtimeNs(fnB));
  }
  return { samplesA, samplesB };
}

function report(name, samplesA, samplesB, labelA, labelB) {
  const trimmedA = trimOutliers(samplesA);
  const trimmedB = trimOutliers(samplesB);
  const result = welchTTest(trimmedA, trimmedB);
  const actualSampleCount = samplesA.length; // FIX: report the real count used for THIS test, not the global default

  console.log(`\n=== ${name} ===`);
  console.log(`  ${labelA}: ortalama=${(result.meanA / 1000).toFixed(2)}µs  std=${(result.stdDevA / 1000).toFixed(2)}µs`);
  console.log(`  ${labelB}: ortalama=${(result.meanB / 1000).toFixed(2)}µs  std=${(result.stdDevB / 1000).toFixed(2)}µs`);
  console.log(`  fark: ${(result.meanDiffNs / 1000).toFixed(3)}µs  |t|=${Math.abs(result.tStatistic).toFixed(2)} (esik: 4.5)`);
  if (result.likelyDistinguishable) {
    console.log(`  ⚠️  SONUÇ: İSTATİSTİKSEL OLARAK AYIRT EDİLEBİLİR - potansiyel zamanlama yan kanalı (timing side-channel)`);
  } else {
    console.log(`  ✅ SONUÇ: |t| eşiğin altında - bu ${actualSampleCount} örneklemde ayırt edilebilir bir zamanlama farkı bulunamadı`);
  }
  return result;
}

async function testAesGcmTagVerification() {
  const masterKeyHex = crypto.randomBytes(32).toString('hex');
  const valid = envelopeEncrypt('timing test payload', 'timing_key', 1, masterKeyHex);

  // METHODOLOGY NOTE (found by testing, corrected accordingly): comparing
  // "valid tag" (no exception) vs "invalid tag" (throws) is CONFOUNDED -
  // a side experiment measuring plain JS throw/catch overhead alone
  // showed ~2µs difference with |t|=128, unrelated to any cryptography.
  // That overhead would swamp a much smaller real signal.
  //
  // The methodologically correct test: compare two DIFFERENT invalid
  // tags that both throw, differing only in WHERE the mismatch is
  // (first byte vs last byte). Both samples pay identical exception
  // overhead, so this isolates whether OpenSSL's tag comparison itself
  // leaks the mismatch position via timing (the classic early-exit
  // byte-compare vulnerability).
  const tagFirstByteWrong = (flipHexByte(valid.authTagHex, 0));
  const tagLastByteWrong = (flipHexByte(valid.authTagHex, valid.authTagHex.length - 2));

  const payloadA = { ...valid, authTagHex: tagFirstByteWrong };
  const payloadB = { ...valid, authTagHex: tagLastByteWrong };

  const tryDecrypt = (payload) => {
    try { envelopeDecrypt(payload, masterKeyHex); } catch { /* expected - both cases throw equally */ }
  };

  for (let i = 0; i < WARMUP; i++) { tryDecrypt(payloadA); tryDecrypt(payloadB); }
  const { samplesA, samplesB } = collectInterleaved(() => tryDecrypt(payloadA), () => tryDecrypt(payloadB), SAMPLES);
  return report('AES-256-GCM Tag Karşılaştırması: ilk-bayt-hatalı vs son-bayt-hatalı (her ikisi de exception fırlatır)', samplesA, samplesB, 'ilk bayt hatalı', 'son bayt hatalı');
}

function flipHexByte(hex, charOffset) {
  const c = hex[charOffset];
  const flipped = c === '0' ? '1' : '0';
  return hex.slice(0, charOffset) + flipped + hex.slice(charOffset + 1);
}

async function testHsmVerifyTiming() {
  let hsmSign, hsmVerify;
  try {
    ({ hsmSign, hsmVerify } = await import('../src/hsm-bridge.js'));
    hsmSign('01', 'timing-test-init'); // will throw if HSM not configured - caught below
  } catch (e) {
    console.log('\n=== HSM PKCS#11 İmza Doğrulama ===');
    console.log(`  Atlandı: HSM yapılandırılmamış (${e.message.split('\n')[0]})`);
    console.log('  Bu ortamda test için: HSM_PIN, PKCS11_MODULE_PATH ayarlayıp bir "01" ID li anahtar üretin.');
    return null;
  }

  const message = 'timing analysis message';
  const signed = hsmSign('01', message);
  const tamperedSig = signed.signatureHex.slice(0, -2) + (signed.signatureHex.slice(-2) === '00' ? '01' : '00');

  const tryVerify = (sig) => { try { hsmVerify('01', message, sig); } catch { /* ignore */ } };

  const HSM_SAMPLES = 100; // PKCS#11 round-trips are slow (process spawn) - fewer samples, still statistically meaningful
  for (let i = 0; i < 5; i++) { tryVerify(signed.signatureHex); tryVerify(tamperedSig); }
  const { samplesA, samplesB } = collectInterleaved(() => tryVerify(signed.signatureHex), () => tryVerify(tamperedSig), HSM_SAMPLES);
  return report('HSM PKCS#11 İmza Doğrulama (SoftHSM2)', samplesA, samplesB, 'geçerli imza', 'tahrif edilmiş imza');
}

async function testPqcDecapsTiming() {
  let mlkemKeygen, mlkemEncaps, mlkemDecaps;
  try {
    ({ mlkemKeygen, mlkemEncaps, mlkemDecaps } = await import('../src/pqc-bridge.js'));
    mlkemKeygen();
  } catch (e) {
    console.log('\n=== ML-KEM-1024 Decapsulation Zamanlaması ===');
    console.log(`  Atlandı: PQC bridge derlenmemiş (${e.message.split('\n')[0]})`);
    console.log('  Bu ortamda test için: cd c_pqc && ./build.sh');
    return null;
  }

  const keys = mlkemKeygen();
  const encapsResult = mlkemEncaps(keys.publicKeyHex);
  const tamperedCt = encapsResult.ciphertextHex.slice(0, -2) + (encapsResult.ciphertextHex.slice(-2) === '00' ? '01' : '00');

  const tryDecaps = (ct) => { try { mlkemDecaps(keys.secretKeyHex, ct); } catch { /* ignore */ } };

  const PQC_SAMPLES = 60; // each call spawns the real liboqs C binary - slow but real
  for (let i = 0; i < 3; i++) { tryDecaps(encapsResult.ciphertextHex); tryDecaps(tamperedCt); }
  const { samplesA, samplesB } = collectInterleaved(() => tryDecaps(encapsResult.ciphertextHex), () => tryDecaps(tamperedCt), PQC_SAMPLES);
  return report('ML-KEM-1024 Decapsulation (liboqs)', samplesA, samplesB, 'geçerli ciphertext', 'tahrif edilmiş ciphertext');
}

async function main() {
  console.log('ISHv4 Gerçek Zamanlama Yan Kanalı (Timing Side-Channel) Analizi');
  console.log('Yöntem: dudect tarzı istatistiksel analiz (Welch t-testi, iç içe örnekleme, aykırı değer kırpma)');
  console.log(`Not: Bu kapsamlı bir sızma testi DEĞİLDİR - yalnızca bu projenin kendi kripto işlemlerinin`);
  console.log(`zamanlama tutarlılığını inceler.\n`);

  await testAesGcmTagVerification();
  await testHsmVerifyTiming();
  await testPqcDecapsTiming();

  console.log('\nTamamlandı.');
}

main();
