import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const root = process.cwd();
const version = process.env.ISH_RELEASE_VERSION || '1.3.0-commercial';
const out = path.join(root, 'release', `ishv4-real-kms-${version}`);
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

const include = [
  'server.js', 'package.json', 'package-lock.json', 'README.md', 'SECURITY.md',
  'DATA-HANDLING.md', 'KEY-LIFECYCLE-PROCEDURES.md', 'PRODUCTION-HARDENING-CHECKLIST.md',
  'RELEASE-CHECKLIST.md', 'src', 'services', 'security-agent', 'security', 'public', 'mtls',
  'config/production.env.example', 'docs', 'tests', 'scripts', 'c_pqc', 'rust-wasm-crypto',
  'raft-ledger', 'DEVELOPMENT', 'commercial-extensions'
];
const skip = new Set(['data', 'tmp', 'node_modules', '.git', 'release']);

function copyRecursive(rel) {
  const source = path.join(root, rel);
  const target = path.join(out, rel);
  if (!fs.existsSync(source)) return;
  const stat = fs.statSync(source);
  if (stat.isDirectory()) {
    fs.mkdirSync(target, { recursive: true });
    for (const entry of fs.readdirSync(source)) {
      if (!skip.has(entry)) copyRecursive(path.join(rel, entry));
    }
  } else {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(source, target);
  }
}

for (const item of include) copyRecursive(item);

const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else files.push(path.relative(out, full));
  }
}
walk(out);
files.sort();
const sums = files.map((file) => `${crypto.createHash('sha256').update(fs.readFileSync(path.join(out, file))).digest('hex')}  ${file}`).join('\n') + '\n';
fs.writeFileSync(path.join(out, 'SHA256SUMS.txt'), sums);
fs.writeFileSync(path.join(out, 'VERSION.txt'), `ishv4-real-kms ${version}\nISHWALL + ISHLOCK + Threat Intelligence Fabric + Commercial Licensing\n`);
fs.writeFileSync(path.join(out, 'COMMERCIAL-RELEASE.txt'), [
  'ISH Commercial Release',
  `Release: ${version}`,
  'Payment: manual IBAN reconciliation',
  'License: Ed25519-signed, HWID-bound',
  'Bank API: not assumed or fabricated',
  'Production secrets: environment/secret store only',
  'Artifact integrity: SHA-256 manifest',
  'Source provenance: Git commit + GitHub Actions release workflow'
].join('\n') + '\n');
console.log(out);
