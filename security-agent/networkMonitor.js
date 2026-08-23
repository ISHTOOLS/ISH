import fs from 'node:fs';
export function scanNetwork() {
  const findings=[]; try { const data=fs.readFileSync('/proc/net/tcp','utf8'); for(const line of data.split('\n').slice(1)) if(line.trim()) findings.push({source:'proc_net_tcp',state:line.trim().split(/\s+/)[3]||'unknown'}); } catch {}
  return findings;
}
