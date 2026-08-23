import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanProcesses } from '../security-agent/processMonitor.js';
import { scanNetwork } from '../security-agent/networkMonitor.js';
import { scanFiles } from '../security-agent/fileScanner.js';
import { logEvent } from '../src/audit.js';
import { getRequestContext } from '../src/request-context.js';
import { assertTenantAccess } from '../src/tenant-guard.js';

const MAX_PATHS = 100;
const MAX_FINDINGS = 200;
const MAX_PERSISTENCE_ENTRIES = 100;
const MAX_NETWORK_ALERTS = 200;
const SUSPICIOUS_PROCESS_PATTERNS = [
  /(^|[\\/])(keylog(?:ger)?|meterpreter|cobalt(?:strike)?|mimikatz|frida(?:-server)?)(?:$|[\\/ ._-])/i,
  /(?:^|[\\/])(tmp|var[\\/]tmp|dev[\/]shm)(?:[\\/]|$)/i,
  /(?:^|[\s\/])(?:powershell|cmd|wscript|cscript)(?:\.exe)?(?:[\s\/]|$)/i,
];
const SENSITIVE_ASSIGNMENT = /((?:password|passwd|token|api[_-]?key|secret|authorization|bearer|private[_-]?key)\s*[=:]\s*)[^\s&]+/gi;

function safe(value, max = 512) {
  return String(value ?? '')
    .replace(SENSITIVE_ASSIGNMENT, '$1[REDACTED]')
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, max);
}

function findingLimit(items, limit = MAX_FINDINGS) {
  return items.slice(0, limit);
}

function detectPrivilege() {
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-Command',
        '[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() | % { $_.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }'
      ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 3000 });
      const value = out.trim().toLowerCase();
      if (value === 'true') return { detected: true, supported: true };
      if (value === 'false') return { detected: false, supported: true };
    } catch {
      return { detected: null, supported: false };
    }
    return { detected: null, supported: false };
  }
  if (typeof process.getuid === 'function') return { detected: process.getuid() === 0, supported: true };
  return { detected: null, supported: false };
}

function readLinuxProcess(pid) {
  const base = `/proc/${pid}`;
  let name = String(pid);
  let command = '';
  let executablePath = null;
  let parentPid = null;
  let uid = null;
  try { name = fs.readFileSync(`${base}/comm`, 'utf8').trim() || name; } catch {}
  try { command = fs.readFileSync(`${base}/cmdline`, 'utf8').replace(/\0/g, ' ').trim(); } catch {}
  try { executablePath = fs.readlinkSync(`${base}/exe`); } catch (err) { if (err.code === 'ENOENT') executablePath = null; }
  try {
    const status = fs.readFileSync(`${base}/status`, 'utf8');
    const ppid = status.match(/^PPid:\s+(\d+)/m); if (ppid) parentPid = Number(ppid[1]);
    const uidLine = status.match(/^Uid:\s+(\d+)/m); if (uidLine) uid = Number(uidLine[1]);
  } catch {}
  return { pid: Number(pid), name: safe(name, 160), path: safe(executablePath || '', 512) || null, command: safe(command, 512), parentPid, uid };
}

function analyzeProcesses() {
  if (process.platform === 'linux' && fs.existsSync('/proc')) {
    const findings = [];
    let entries = [];
    try { entries = fs.readdirSync('/proc').filter(x => /^\d+$/.test(x)); } catch { return { findings: [], supported: false }; }
    for (const pid of entries) {
      const p = readLinuxProcess(pid);
      const reasons = [];
      const commandOrPath = `${p.path || ''} ${p.command}`;
      const highConfidence = [];
      if (/(^|[\\/])(keylog(?:ger)?|meterpreter|cobalt(?:strike)?|mimikatz|frida(?:-server)?)(?:$|[\\/ ._-])/i.test(commandOrPath)) {
        reasons.push('known suspicious tool/process pattern'); highConfidence.push('known suspicious tool/process pattern');
      }
      if (/(?:^|[\s\/])(?:powershell|cmd|wscript|cscript)(?:\.exe)?(?:[\s\/]|$)/i.test(commandOrPath)) reasons.push('scripting host process');
      if (/(?:^|[\s=])\/(?:tmp|var\/tmp|dev\/shm)\//i.test(commandOrPath)) reasons.push('temporary executable or command path');
      try { if (p.path && fs.realpathSync(p.path) !== p.path) reasons.push('executable path resolves differently'); } catch {}
      if (p.path && /\.(deleted)$/i.test(p.path)) { reasons.push('deleted executable'); highConfidence.push('deleted executable'); }
      if (p.uid === 0 && p.path && /\/(tmp|dev\/shm|var\/tmp)\//.test(p.path)) { reasons.push('privileged process from temporary location'); highConfidence.push('privileged process from temporary location'); }
      if (reasons.length) findings.push({ pid: p.pid, name: p.name, path: p.path, parentPid: p.parentPid, reasons: [...new Set(reasons)], confidence: highConfidence.length ? 'high' : 'medium' });
    }
    return { findings: findingLimit(findings), supported: true };
  }
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-Command',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress'
      ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
      const parsed = JSON.parse(out || '[]');
      const list = Array.isArray(parsed) ? parsed : [parsed];
      const findings = [];
      for (const p of list) {
        const text = `${p.Name || ''} ${p.ExecutablePath || ''} ${p.CommandLine || ''}`;
        const reasons = SUSPICIOUS_PROCESS_PATTERNS.filter(rx => rx.test(text)).map(() => 'suspicious executable or command pattern');
        if (!p.ExecutablePath) reasons.push('executable path unavailable');
        if (reasons.length) findings.push({ pid: Number(p.ProcessId), name: safe(p.Name, 160), path: safe(p.ExecutablePath, 512) || null, parentPid: Number(p.ParentProcessId) || null, reasons: [...new Set(reasons)] });
      }
      return { findings: findingLimit(findings), supported: true };
    } catch { return { findings: [], supported: false }; }
  }
  return { findings: [], supported: false };
}

function parseLinuxNetwork() {
  const records = [];
  for (const proto of ['tcp', 'tcp6']) {
    try {
      const lines = fs.readFileSync(`/proc/net/${proto}`, 'utf8').trim().split('\n').slice(1);
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 10) continue;
        const [localHex, remoteHex, state] = [cols[1], cols[2], cols[3]];
        const decode = (v) => {
          const [addr, portHex] = v.split(':');
          const port = parseInt(portHex, 16);
          if (!Number.isFinite(port)) return null;
          if (proto === 'tcp') {
            const bytes = addr.match(/../g)?.map(x => parseInt(x, 16)).reverse();
            return { address: bytes?.join('.') || addr, port };
          }
          return { address: addr, port };
        };
        const local = decode(localHex); const remote = decode(remoteHex);
        if (local && remote) records.push({ protocol: proto, local, remote, state });
      }
    } catch {}
  }
  return records;
}

function analyzeNetwork() {
  if (process.platform === 'linux' && fs.existsSync('/proc/net/tcp')) {
    const alerts = [];
    for (const c of parseLinuxNetwork()) {
      const listening = c.state === '0A';
      const establishedExternal = c.state === '01' && !['127.0.0.1', '0.0.0.0'].includes(c.remote.address) && !c.remote.address.startsWith('::1');
      if (listening || establishedExternal) {
        alerts.push({ protocol: c.protocol, local: c.local, remote: c.remote, state: c.state, reasons: [listening ? 'listening socket' : 'external established connection'] });
      }
    }
    return { alerts: alerts.slice(0, MAX_NETWORK_ALERTS), supported: true };
  }
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('netstat.exe', ['-ano', '-p', 'tcp'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
      const alerts = [];
      for (const line of out.split(/\r?\n/)) {
        const m = line.trim().match(/^TCP\s+(\S+)\s+(\S+)\s+(LISTENING|ESTABLISHED)\s+(\d+)$/i);
        if (!m) continue;
        const [, localRaw, remoteRaw, state, pid] = m;
        const remoteHost = remoteRaw.replace(/:\d+$/, '');
        const listening = state.toUpperCase() === 'LISTENING';
        const external = state.toUpperCase() === 'ESTABLISHED' && !/^127\.0\.0\.1$|^\[?::1\]?$/i.test(remoteHost);
        if (listening || external) alerts.push({ protocol: 'tcp', local: localRaw, remote: remoteRaw, state: state.toUpperCase(), pid: Number(pid), reasons: [listening ? 'listening socket' : 'external established connection'] });
      }
      return { alerts: alerts.slice(0, MAX_NETWORK_ALERTS), supported: true };
    } catch { return { alerts: [], supported: false }; }
  }
  return { alerts: [], supported: false };
}

function listDirEntries(dir) {
  try { return fs.readdirSync(dir, { withFileTypes: true }).slice(0, MAX_PERSISTENCE_ENTRIES); } catch { return []; }
}

function persistenceTextIsSuspicious(text) {
  return /(?:^|[\s=])\/(?:tmp|var\/tmp|dev\/shm)\/|(?:^|[\s=])(curl|wget)\s+|powershell(?:\.exe)?\s+-enc|base64\s+-d/i.test(text);
}

function analyzePersistence() {
  const findings = [];
  if (process.platform === 'linux') {
    const dirs = [
      '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly',
      '/etc/systemd/system', '/usr/lib/systemd/system',
      path.join(os.homedir(), '.config', 'autostart'),
      path.join(os.homedir(), '.config', 'systemd', 'user'),
    ];
    for (const dir of dirs) {
      for (const entry of listDirEntries(dir)) {
        const full = path.join(dir, entry.name);
        if (!entry.isFile()) continue;
        let content = '';
        try { content = fs.readFileSync(full, 'utf8').slice(0, 64 * 1024); } catch {}
        if (persistenceTextIsSuspicious(content)) {
          findings.push({ path: safe(full), type: 'file', reasons: ['suspicious persistence command or target'] });
        }
      }
    }
    for (const file of ['/etc/crontab']) {
      try {
        if (fs.statSync(file).isFile()) {
          const content = fs.readFileSync(file, 'utf8').slice(0, 64 * 1024);
          if (persistenceTextIsSuspicious(content)) findings.push({ path: file, type: 'file', reasons: ['suspicious cron command or target'] });
        }
      } catch {}
    }
    return { findings: findingLimit(findings), supported: true };
  }
  if (process.platform === 'win32') {
    try {
      const out = execFileSync('schtasks.exe', ['/Query', '/FO', 'CSV', '/NH'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 7000 });
      for (const line of out.split(/\r?\n/).slice(0, MAX_PERSISTENCE_ENTRIES)) {
        const m = line.match(/^"([^"]+)"/);
        if (m && persistenceTextIsSuspicious(line)) findings.push({ path: safe(m[1]), type: 'scheduled-task', reasons: ['suspicious scheduled task command or target'] });
      }
      return { findings: findingLimit(findings), supported: true };
    } catch { return { findings: [], supported: false }; }
  }
  return { findings: [], supported: false };
}

function validatePaths(paths) {
  if (!Array.isArray(paths)) throw Object.assign(new Error('Invalid file paths'), { code: 'SPYWARE_INVALID_INPUT', statusCode: 400, isOperational: true });
  return paths.slice(0, MAX_PATHS).filter(p => {
    if (typeof p !== 'string' || p.length === 0 || p.length > 1024) return false;
    const normalized = path.normalize(p);
    return normalized === p || !/(^|[\\/])\.\.(?:[\\/]|$)/.test(p);
  }).map(p => path.resolve(p));
}

export function runSpywareDefender({ paths = [], tenantId = null } = {}) {
  const context = getRequestContext();
  if (tenantId !== null) assertTenantAccess(tenantId, { resourcePath: '/api/security/spyware-scan' });
  const privilege = detectPrivilege();
  const processAnalysis = analyzeProcesses();
  const networkAnalysis = analyzeNetwork();
  const persistence = analyzePersistence();
  const safePaths = validatePaths(paths);
  const integrity = safePaths.length ? scanFiles(safePaths) : [];

  // Reuse the existing monitors as an additional real-system probe. Their
  // results are intentionally not copied into the audit payload.
  let processProbe = [];
  let networkProbe = [];
  try { processProbe = scanProcesses(); } catch {}
  try { networkProbe = scanNetwork(); } catch {}

  const suspiciousProcesses = processAnalysis.findings;
  const networkAlerts = networkAnalysis.alerts;
  const persistenceFindings = persistence.findings;
  const compromised = suspiciousProcesses.some(p => p.confidence === 'high') || persistenceFindings.length > 0;

  const result = {
    compromised,
    rootDetected: privilege.detected,
    suspiciousProcesses,
    networkAlerts,
    persistenceFindings,
  };

  logEvent({
    action: 'SPYWARE_DEFENDER_SCAN',
    status: 'SUCCESS',
    resourcePath: '/api/security/spyware-scan',
    tenantId: context.tenantId || '',
    userId: context.userId || 'system',
    details: `processes=${suspiciousProcesses.length} network=${networkAlerts.length} persistence=${persistenceFindings.length} integrity=${integrity.length} processProbe=${processProbe.length} networkProbe=${networkProbe.length} privilegeSupported=${privilege.supported} persistenceSupported=${persistence.supported} networkSupported=${networkAnalysis.supported}`,
  });
  return result;
}
