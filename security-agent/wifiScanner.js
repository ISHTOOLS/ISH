import { execFileSync } from 'node:child_process';
export function scanWifi() {
  try { const output=execFileSync('iw',['dev'],{encoding:'utf8',timeout:1500,stdio:['ignore','pipe','ignore']}); return output.split('\n').filter(Boolean).slice(0,100).map(interfaceLine=>({interface:interfaceLine.trim()})); } catch { return []; }
}
