import dgram from 'dgram';
import net from 'net';

/**
 * Real-time SIEM push adapter. Unlike /api/audit/export (pull-based, on
 * request), this pushes each audit event to a configured SIEM collector
 * the moment it's recorded, using RFC 5424 syslog framing with a CEF
 * payload - the standard transport Splunk, QRadar, and Wazuh's log
 * collector all listen on.
 *
 * Decentralization note: this is a fan-out sender, not a single point of
 * failure for the audit trail itself - the local HMAC-chained
 * data/audit.log (see src/audit.js) remains the durable, tamper-evident
 * source of truth regardless of whether the SIEM is reachable. If the
 * SIEM is down, pushes are dropped (logged locally) but the local chain
 * is never affected - this mirrors how real syslog-based integrations
 * behave (UDP syslog is fire-and-forget by design).
 */

const PRI = 14; // facility=1 (user-level), severity=6 (informational) by default - overridden per event below

function rfc5424Frame(cefMessage, hostname, appName) {
  const pri = PRI;
  const version = 1;
  const timestamp = new Date().toISOString();
  const msgId = '-';
  const structuredData = '-';
  return `<${pri}>${version} ${timestamp} ${hostname} ${appName} - ${msgId} ${structuredData} ${cefMessage}`;
}

export function createSiemPusher({ host, port, protocol = 'udp', hostname = 'ishv4-kms', appName = 'ISHv4' }) {
  if (!host || !port) {
    return { push: () => {}, enabled: false };
  }

  let tcpSocket = null;
  function getTcpSocket() {
    if (tcpSocket && !tcpSocket.destroyed) return tcpSocket;
    tcpSocket = net.createConnection({ host, port });
    tcpSocket.on('error', () => {}); // fire-and-forget: SIEM downtime must never affect the KMS
    return tcpSocket;
  }

  function push(cefMessage) {
    const framed = rfc5424Frame(cefMessage, hostname, appName);
    try {
      if (protocol === 'tcp') {
        getTcpSocket().write(framed + '\n');
      } else {
        const client = dgram.createSocket('udp4');
        const buf = Buffer.from(framed);
        client.send(buf, 0, buf.length, port, host, () => client.close());
      }
    } catch {
      // Intentionally swallowed - a SIEM being unreachable must never
      // break or slow down KMS operations. The durable audit trail is
      // data/audit.log, not this push channel.
    }
  }

  return { push, enabled: true, host, port, protocol };
}
