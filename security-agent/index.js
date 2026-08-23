import os from 'node:os';
import { logEvent } from '../src/audit.js';
import { scanNetwork } from './networkMonitor.js';
import { scanProcesses } from './processMonitor.js';
import { scanWifi } from './wifiScanner.js';
import { scanFiles } from './fileScanner.js';
export function runSecurityScan({files=[]}={}) {
  const result={timestamp:new Date().toISOString(),hostname:os.hostname(),network:scanNetwork(),wifi:scanWifi(),processes:scanProcesses(),files:scanFiles(files),policy:{autoKill:false,autoQuarantine:true,logOnly:false}};
  logEvent({action:'SECURITY_AGENT_SCAN',status:'SUCCESS',resourcePath:'/security-agent/scan',details:`network=${result.network.length} processes=${result.processes.length}`});
  return result;
}
