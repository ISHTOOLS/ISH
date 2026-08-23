import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const PORT = 4098;
const DATA_DIR = path.resolve('data-loadtest');
const LOG_DIR = path.resolve('security-audit', 'runtime');
const STDOUT_LOG = path.join(LOG_DIR, 'load-test.stdout.log');
const STDERR_LOG = path.join(LOG_DIR, 'load-test.stderr.log');

fs.rmSync(DATA_DIR, { recursive: true, force: true });
fs.rmSync(LOG_DIR, { recursive: true, force: true });

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

const stdoutFd = fs.openSync(STDOUT_LOG, 'w');
const stderrFd = fs.openSync(STDERR_LOG, 'w');

const server = spawn('node', ['server.js'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    ISHV4_DATA_DIR: DATA_DIR,
  },
  stdio: ['ignore', stdoutFd, stderrFd],
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForServer(url, timeoutMs = 15000) {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    try {
      const response = await fetch(url);

      if (response.status >= 200 && response.status < 500) {
        return;
      }
    } catch {
      // Server is still starting.
    }

    await sleep(250);
  }

  throw new Error(`Server did not become ready within ${timeoutMs}ms`);
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, options);

  let body = null;

  try {
    body = await response.json();
  } catch {
    body = null;
  }

  return {
    status: response.status,
    body,
  };
}

function percentile(values, percentileValue) {
  if (values.length === 0) {
    return 0;
  }

  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1),
  );

  return sorted[index];
}

function createStats() {
  return {
    total: 0,
    successful: 0,
    failed: 0,
    errors: 0,
    statusCodes: new Map(),
    latencies: [],
  };
}

function recordResult(stats, status, latency) {
  stats.total += 1;
  stats.latencies.push(latency);

  const key = String(status);
  stats.statusCodes.set(key, (stats.statusCodes.get(key) || 0) + 1);

  if (status >= 200 && status < 300) {
    stats.successful += 1;
  } else {
    stats.failed += 1;
  }
}

function recordError(stats, latency = 0) {
  stats.total += 1;
  stats.errors += 1;
  stats.failed += 1;
  stats.latencies.push(latency);
}

function formatStats(stats) {
  const average =
    stats.latencies.length === 0
      ? 0
      : stats.latencies.reduce((sum, value) => sum + value, 0) /
        stats.latencies.length;

  return {
    total: stats.total,
    successful: stats.successful,
    failed: stats.failed,
    errors: stats.errors,
    statusCodeStats: Object.fromEntries(
      [...stats.statusCodes.entries()].sort(([a], [b]) =>
        a.localeCompare(b, undefined, { numeric: true }),
      ),
    ),
    latency: {
      average: Number(average.toFixed(2)),
      p50: percentile(stats.latencies, 50),
      p95: percentile(stats.latencies, 95),
      p99: percentile(stats.latencies, 99),
    },
  };
}

async function requestOnce(url, body, stats) {
  const started = performance.now();

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const latency = performance.now() - started;

    // Consume the response body so the connection can be reused.
    try {
      await response.arrayBuffer();
    } catch {
      // Ignore body-consumption errors; the request result is still recorded.
    }

    recordResult(stats, response.status, latency);
  } catch {
    const latency = performance.now() - started;
    recordError(stats, latency);
  }
}

async function runOverload(url, body) {
  const stats = createStats();
  const durationMs = 4000;
  const connections = 20;
  const deadline = Date.now() + durationMs;

  async function worker() {
    while (Date.now() < deadline) {
      await requestOnce(url, body, stats);
    }
  }

  await Promise.all(
    Array.from({ length: connections }, () => worker()),
  );

  return stats;
}

async function runSustained(url, body) {
  const stats = createStats();
  const durationMs = 4000;
  const overallRate = 7;
  const intervalMs = 1000 / overallRate;
  const deadline = Date.now() + durationMs;

  while (Date.now() < deadline) {
    const started = Date.now();

    await requestOnce(url, body, stats);

    const elapsed = Date.now() - started;
    const remaining = Math.max(0, intervalMs - elapsed);

    if (Date.now() + remaining < deadline) {
      await sleep(remaining);
    }
  }

  return stats;
}

function printScenario(name, stats) {
  const result = formatStats(stats);

  console.log(`\n== ${name} ==`);
  console.log('Toplam istek:', result.total);
  console.log('Başarılı:', result.successful);
  console.log('Başarısız:', result.failed);
  console.log('Ağ/istemci hatası:', result.errors);
  console.log('Durum kodu dağılımı:', JSON.stringify(result.statusCodeStats));
  console.log(
    'Gecikme (ort/p50/p95/p99):',
    result.latency.average,
    '/',
    result.latency.p50,
    '/',
    result.latency.p95,
    '/',
    result.latency.p99,
    'ms',
  );
}

let exitCode = 0;

try {
  console.log('ISHV4 load test başlatılıyor...');
  console.log('Data directory:', DATA_DIR);

  await waitForServer(`http://localhost:${PORT}/health`);

  console.log('Server hazır.');

  const init = await jsonRequest(
    `http://localhost:${PORT}/api/vault/init`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        thresholdK: 2,
        totalSharesN: 3,
      }),
    },
  );

  if (init.status < 200 || init.status >= 300 || !init.body?.shares) {
    throw new Error(
      `Vault initialization failed with HTTP ${init.status}`,
    );
  }

  for (const share of init.body.shares.slice(0, 2)) {
    const unseal = await jsonRequest(
      `http://localhost:${PORT}/api/vault/unseal`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          shareIndex: share.index,
          shareHex: share.shareHex,
        }),
      },
    );

    if (unseal.status < 200 || unseal.status >= 300) {
      throw new Error(
        `Vault unseal failed with HTTP ${unseal.status}`,
      );
    }
  }

  const key = await jsonRequest(
    `http://localhost:${PORT}/api/kms/keys`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        alias: 'loadtest',
      }),
    },
  );

  if (key.status < 200 || key.status >= 300) {
    throw new Error(
      `KMS key creation failed with HTTP ${key.status}`,
    );
  }

  const encryptUrl = `http://localhost:${PORT}/api/kms/encrypt`;

  console.log(
    '\n== SENARYO 1: Aşırı yükleme (20 bağlantı, maksimum hız, 4sn) ==',
  );

  const overload = await runOverload(encryptUrl, {
    alias: 'loadtest',
    plaintext: 'overload test',
  });

  printScenario('SENARYO 1: Aşırı yükleme', overload);

  console.log(
    '\n== SENARYO 2: Sürdürülebilir hız (yaklaşık 7 istek/sn, 4sn) ==',
  );

  const sustained = await runSustained(encryptUrl, {
    alias: 'loadtest',
    plaintext: 'sustainable test',
  });

  printScenario('SENARYO 2: Sürdürülebilir hız', sustained);

  console.log('\nLoad test tamamlandı.');
} catch (error) {
  exitCode = 1;

  console.error(
    'Load test başarısız:',
    error instanceof Error ? error.message : String(error),
  );
} finally {
  try {
    server.kill('SIGTERM');
  } catch {
    // Server may already have exited.
  }

  await sleep(500);

  try {
    if (!server.killed) {
      server.kill('SIGKILL');
    }
  } catch {
    // Ignore cleanup errors.
  }

  try {
    fs.closeSync(stdoutFd);
  } catch {
    // Ignore.
  }

  try {
    fs.closeSync(stderrFd);
  } catch {
    // Ignore.
  }

  fs.rmSync(DATA_DIR, { recursive: true, force: true });
}

process.exit(exitCode);