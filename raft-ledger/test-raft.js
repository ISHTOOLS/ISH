import { spawn } from 'child_process';
import fs from 'fs';

const env = { ...process.env, RAFT_ELECTION_MIN_MS: '300', RAFT_ELECTION_MAX_MS: '600', RAFT_HEARTBEAT_MS: '100' };

fs.rmSync('raft-data', { recursive: true, force: true });

const nodes = {
  A: spawn('node', ['raft-node.js', 'A', '5001', 'http://localhost:5002', 'http://localhost:5003'], { env }),
  B: spawn('node', ['raft-node.js', 'B', '5002', 'http://localhost:5001', 'http://localhost:5003'], { env }),
  C: spawn('node', ['raft-node.js', 'C', '5003', 'http://localhost:5001', 'http://localhost:5002'], { env }),
};
const ports = { A: 5001, B: 5002, C: 5003 };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function status(name) {
  try {
    const res = await fetch(`http://localhost:${ports[name]}/status`, { signal: AbortSignal.timeout(1000) });
    return res.json();
  } catch {
    return null;
  }
}
async function submit(name, command) {
  const res = await fetch(`http://localhost:${ports[name]}/submit`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ command }), signal: AbortSignal.timeout(1000),
  });
  return res.json();
}

async function findLeader(excluding = []) {
  for (const name of Object.keys(nodes)) {
    if (excluding.includes(name)) continue;
    const s = await status(name);
    if (s && s.role === 'leader') return name;
  }
  return null;
}

async function main() {
  console.log('== 3 node kumesi baslatiliyor ==');
  await sleep(1200);

  const leader1 = await findLeader();
  console.log('ILK LIDER:', leader1);
  if (!leader1) { console.log('SONUC: BASARISIZ - lider secilemedi'); cleanup(); return; }

  await submit(leader1, 'ENTRY_1: vault init');
  await submit(leader1, 'ENTRY_2: key created');
  await sleep(500);

  console.log('== Replikasyon sonrasi durum ==');
  for (const name of Object.keys(nodes)) {
    const s = await status(name);
    console.log(` ${name}: commitIndex=${s.commitIndex} log=${JSON.stringify(s.committedLog.map(e => e.command))}`);
  }

  console.log(`== Lider (${leader1}) olduruluyor ==`);
  nodes[leader1].kill('SIGKILL');
  await sleep(1500);

  const leader2 = await findLeader([leader1]);
  console.log('YENI LIDER:', leader2);
  if (!leader2) { console.log('SONUC: BASARISIZ - yeniden secim olmadi'); cleanup(); return; }
  if (leader2 === leader1) { console.log('SONUC: SUPHELI - olu node hala lider gorunuyor'); }

  await submit(leader2, 'ENTRY_3: after leader failure');
  await sleep(500);

  console.log('== Son durum (veri kaybi kontrolu) ==');
  let allMatch = true;
  let reference = null;
  for (const name of Object.keys(nodes)) {
    if (name === leader1) continue;
    const s = await status(name);
    const commands = s.committedLog.map(e => e.command);
    console.log(` ${name}: commitIndex=${s.commitIndex} log=${JSON.stringify(commands)}`);
    if (reference === null) reference = JSON.stringify(commands);
    else if (JSON.stringify(commands) !== reference) allMatch = false;
    if (commands.length !== 3) allMatch = false;
  }

  console.log('');
  console.log(allMatch
    ? 'SONUC: BASARILI - lider oldu, yeniden secim oldu, kume calismaya devam etti, TUM 3 kayit hicbir veri kaybi olmadan tum hayatta kalan node larda mevcut.'
    : 'SONUC: BASARISIZ - node lar arasinda tutarsizlik veya veri kaybi var.');

  cleanup();
}

function cleanup() {
  for (const n of Object.values(nodes)) { try { n.kill('SIGKILL'); } catch {} }
  setTimeout(() => process.exit(0), 300);
}

main();
