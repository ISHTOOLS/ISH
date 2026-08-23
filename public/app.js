const $ = (id) => document.getElementById(id);

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

let lastEncryptResult = null;

async function refreshStatus() {
  try {
    const s = await api('GET', '/api/vault/status');
    $('statusBox').textContent = JSON.stringify(s, null, 2);
    const badge = $('vaultBadge');
    if (!s.initialized) {
      badge.textContent = 'başlatılmamış';
      badge.className = 'badge uninitialized';
    } else if (s.sealed) {
      badge.textContent = `mühürlü (${s.sharesSubmitted}/${s.thresholdK} parça)`;
      badge.className = 'badge sealed';
    } else {
      badge.textContent = 'mühür açık';
      badge.className = 'badge unsealed';
    }
    return s;
  } catch (e) {
    $('statusBox').textContent = 'Hata: ' + e.message;
  }
}

$('refreshStatusBtn').onclick = refreshStatus;

$('initBtn').onclick = async () => {
  try {
    const thresholdK = Number($('initK').value);
    const totalSharesN = Number($('initN').value);
    const result = await api('POST', '/api/vault/init', { thresholdK, totalSharesN });
    const box = $('initOutput');
    box.hidden = false;
    box.textContent =
      '⚠ ' + result.warning + '\n\n' +
      result.shares.map((s) => `Parça #${s.index}: ${s.shareHex}`).join('\n');
    refreshStatus();
  } catch (e) {
    alert('Init hatası: ' + e.message);
  }
};

$('unsealBtn').onclick = async () => {
  try {
    const shareIndex = Number($('unsealIndex').value);
    const shareHex = $('unsealShare').value.trim();
    const result = await api('POST', '/api/vault/unseal', { shareIndex, shareHex });
    const box = $('unsealOutput');
    box.hidden = false;
    box.textContent = JSON.stringify(result, null, 2);
    refreshStatus();
    loadKeys();
  } catch (e) {
    $('unsealOutput').hidden = false;
    $('unsealOutput').textContent = 'Hata: ' + e.message;
  }
};

$('sealBtn').onclick = async () => {
  try {
    await api('POST', '/api/vault/seal', {});
    refreshStatus();
  } catch (e) {
    alert(e.message);
  }
};

async function loadKeys() {
  try {
    const { keys } = await api('GET', '/api/kms/keys');
    const tbody = document.querySelector('#keysTable tbody');
    tbody.innerHTML = keys.map(k => `<tr>
      <td>${k.alias}</td><td>${k.algorithm}</td><td>v${k.version}</td>
      <td><button data-alias="${k.alias}" class="rotateBtn">rotate</button></td>
    </tr>`).join('');
    document.querySelectorAll('.rotateBtn').forEach(btn => {
      btn.onclick = async () => {
        await api('POST', `/api/kms/keys/${btn.dataset.alias}/rotate`, {});
        loadKeys();
      };
    });
  } catch (e) { /* vault likely not initialized yet */ }
}

$('createKeyBtn').onclick = async () => {
  try {
    await api('POST', '/api/kms/keys', { alias: $('keyAlias').value, algorithm: $('keyAlgo').value });
    loadKeys();
  } catch (e) {
    alert('Hata: ' + e.message);
  }
};

async function loadSecrets() {
  try {
    const { secrets } = await api('GET', '/api/kms/secrets');
    const tbody = document.querySelector('#secretsTable tbody');
    tbody.innerHTML = secrets.map(s => `<tr><td>${s.id}</td><td>${s.alias}</td><td>${s.algorithm}</td><td>v${s.kekVersion}</td></tr>`).join('');
  } catch (e) {}
}

$('encryptBtn').onclick = async () => {
  try {
    const alias = $('encAlias').value.trim();
    const plaintext = $('encPlaintext').value;
    const result = await api('POST', '/api/kms/encrypt', { alias, plaintext });
    lastEncryptResult = result;
    const box = $('encryptOutput');
    box.hidden = false;
    box.textContent = JSON.stringify(result, null, 2);
    loadSecrets();
  } catch (e) {
    $('encryptOutput').hidden = false;
    $('encryptOutput').textContent = 'Hata: ' + e.message;
  }
};

$('decryptBtn').onclick = async () => {
  try {
    const id = $('decId').value.trim();
    const result = await api('POST', '/api/kms/decrypt', { id });
    const box = $('decryptOutput');
    box.hidden = false;
    box.textContent = JSON.stringify(result, null, 2);
  } catch (e) {
    $('decryptOutput').hidden = false;
    $('decryptOutput').textContent = 'Hata: ' + e.message;
  }
};

$('tamperBtn').onclick = async () => {
  if (!lastEncryptResult) {
    alert('Önce bir şey şifreleyin, sonra tahrif testini deneyin.');
    return;
  }
  const tampered = { ...lastEncryptResult };
  // flip the last hex character of the ciphertext to simulate tampering
  const ct = tampered.ciphertextHex;
  const lastChar = ct.slice(-1);
  const flipped = lastChar === '0' ? '1' : '0';
  tampered.ciphertextHex = ct.slice(0, -1) + flipped;

  try {
    const result = await api('POST', '/api/kms/decrypt', { payload: tampered });
    $('decryptOutput').hidden = false;
    $('decryptOutput').textContent = 'BEKLENMEYEN: tahrif edilmiş veri hatasız çözüldü!\n' + JSON.stringify(result, null, 2);
  } catch (e) {
    $('decryptOutput').hidden = false;
    $('decryptOutput').textContent = '✅ Beklenen davranış: GCM auth tag tahrifatı yakaladı ve reddetti.\nHata mesajı: ' + e.message;
  }
};

$('signBtn').onclick = async () => {
  try {
    const message = $('signMsg').value;
    const result = await api('POST', '/api/crypto/ed25519/sign', { message });
    const box = $('signOutput');
    box.hidden = false;
    box.textContent = JSON.stringify(result, null, 2);
  } catch (e) {
    alert(e.message);
  }
};

$('x25519Btn').onclick = async () => {
  try {
    const result = await api('POST', '/api/crypto/x25519/exchange', {});
    const box = $('x25519Output');
    box.hidden = false;
    box.textContent = JSON.stringify(result, null, 2);
  } catch (e) {
    alert(e.message);
  }
};

$('refreshAuditBtn').onclick = async () => {
  const { logs } = await api('GET', '/api/audit/logs');
  const tbody = document.querySelector('#auditTable tbody');
  tbody.innerHTML = logs.map(l => `<tr><td>${l.seq}</td><td>${l.timestamp}</td><td>${l.action}</td><td>${l.resourcePath}</td><td>${l.statusCode}</td></tr>`).join('');
};

$('verifyAuditBtn').onclick = async () => {
  const result = await api('GET', '/api/audit/verify');
  const box = $('auditVerifyOutput');
  box.hidden = false;
  box.textContent = (result.isValid ? '✅ Zincir bütünlüğü doğrulandı.\n' : '❌ ZİNCİR BOZULMUŞ / TAHRİF EDİLMİŞ.\n') + JSON.stringify(result, null, 2);
};

$('hybridBtn').onclick = async () => {
  try {
    const result = await api('POST', '/api/pqc/hybrid-exchange', {});
    $('hybridOutput').hidden = false;
    $('hybridOutput').textContent = JSON.stringify(result, null, 2);
  } catch (e) { alert(e.message); }
};

$('mldsaBtn').onclick = async () => {
  try {
    const keys = await api('POST', '/api/pqc/mldsa/keygen', {});
    const signed = await api('POST', '/api/pqc/mldsa/sign', { secretKeyHex: keys.secretKeyHex, message: 'ML-DSA-87 arayuz testi' });
    const verified = await api('POST', '/api/pqc/mldsa/verify', { publicKeyHex: keys.publicKeyHex, message: 'ML-DSA-87 arayuz testi', signatureHex: signed.signatureHex });
    const tamperedVerify = await api('POST', '/api/pqc/mldsa/verify', { publicKeyHex: keys.publicKeyHex, message: 'TAHRIF EDILMIS MESAJ', signatureHex: signed.signatureHex });
    $('mldsaOutput').hidden = false;
    $('mldsaOutput').textContent = JSON.stringify({ algorithm: keys.algorithm, publicKeyBytes: keys.publicKeyBytes, signatureBytes: signed.signatureBytes, correctMessageVerify: verified.verified, tamperedMessageVerify: tamperedVerify.verified }, null, 2);
  } catch (e) { alert(e.message); }
};

$('hsmCreateBtn').onclick = async () => {
  try {
    const result = await api('POST', '/api/hsm/keys', { keyId: $('hsmKeyId').value, label: $('hsmLabel').value });
    $('hsmOutput').hidden = false;
    $('hsmOutput').textContent = JSON.stringify(result, null, 2);
  } catch (e) { alert(e.message); }
};

$('hsmSignBtn').onclick = async () => {
  try {
    const keyId = $('hsmKeyId').value;
    const message = $('hsmMsg').value;
    const signed = await api('POST', '/api/hsm/sign', { keyId, message });
    const verifyOk = await api('POST', '/api/hsm/verify', { keyId, message, signatureHex: signed.signatureHex });
    const verifyTampered = await api('POST', '/api/hsm/verify', { keyId, message: message + ' [TAHRIF]', signatureHex: signed.signatureHex });
    $('hsmOutput').hidden = false;
    $('hsmOutput').textContent = JSON.stringify({ ...signed, correctVerify: verifyOk.verified, tamperedVerify: verifyTampered.verified }, null, 2);
  } catch (e) { alert(e.message); }
};

refreshStatus();
loadKeys();
loadSecrets();
