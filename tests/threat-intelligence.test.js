import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ishv4-ti-'));
process.env.ISHV4_DATA_DIR = tmp;
process.env.THREAT_INTEL_MAX_EVENTS = '1000';

const ti = await import('../src/threat-intelligence.js');
const hp = await import('../src/honeypot-telemetry.js');
const scan = await import('../src/port-scan-detector.js');

test('threat intelligence ingests real event without plaintext credential storage', () => {
  const e = ti.ingestThreatEvent({ source:'test-sensor', sourceIp:'203.0.113.10', destinationIp:'10.0.0.10', destinationPort:22, protocol:'tcp', service:'ssh', eventType:'credential_attack', username:'root', password:'secret', message:'failed login' });
  assert.equal(e.sourceIp, '203.0.113.10');
  assert.ok(e.credentialFingerprint);
  assert.equal('password' in e, false);
  assert.ok(e.threatScore >= 20);
  assert.ok(['low','medium','high','critical'].includes(e.severity));
});

test('Cowrie adapter maps username/password and SSH service', () => {
  const e = hp.ingestSensorEvent({ eventid:'cowrie.login.failed', src_ip:'198.51.100.2', src_port:44444, username:'root', password:'toor', input:'id' }, 'cowrie');
  assert.equal(e.source, 'cowrie');
  assert.equal(e.service, 'ssh');
  assert.equal(e.username, 'root');
  assert.ok(e.credentialFingerprint);
  assert.equal(e.password, undefined);
});

test('Suricata adapter maps EVE alert fields', () => {
  const e = hp.ingestSensorEvent({ timestamp:new Date().toISOString(), src_ip:'198.51.100.3', src_port:50000, dest_ip:'10.0.0.5', dest_port:445, proto:'TCP', app_proto:'smb', alert:{signature:'SMB probe', severity:3} }, 'suricata');
  assert.equal(e.source, 'suricata');
  assert.equal(e.destinationPort, 445);
  assert.equal(e.service, 'smb');
});

test('port scan detector classifies vertical scans from observed connections', () => {
  let result = null;
  for (let port=1; port<=25; port++) result = scan.observeConnection({sourceIp:'198.51.100.4', destinationIp:'10.0.0.20', destinationPort:port, timestamp:Date.now()});
  assert.equal(result.classification, 'vertical_scan');
});

test('profiles, IOC and campaign stores are populated', () => {
  assert.ok(ti.getThreatProfile('203.0.113.10'));
  assert.ok(ti.listIocs(50).some(x => x.type === 'ips' && x.value === '203.0.113.10'));
  assert.ok(ti.listCampaigns(50).length >= 1);
  assert.ok(ti.getThreatStats().total >= 3);
});
