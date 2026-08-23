import fs from 'node:fs';
export function scanProcesses() {
  const findings=[]; try { for(const name of fs.readdirSync('/proc')) if(/^\d+$/.test(name)) try { const cmd=fs.readFileSync(`/proc/${name}/cmdline`,'utf8').replace(/\0/g,' ').trim(); if(cmd) findings.push({pid:Number(name),command:cmd.slice(0,512)}); } catch {} } catch {}
  return findings;
}
