/**
 * Real honeypot telemetry adapters for T-Pot/Cowrie/Dionaea/Suricata/Zeek-like
 * JSON events. This module never fabricates attacks. It validates and forwards
 * observed telemetry into the ISHv4 Threat Intelligence Fabric.
 */
import { ingestThreatEvent, ingestBatch } from './threat-intelligence.js';

function parseMaybeJson(body) {
  if (typeof body === 'object' && body !== null) return body;
  if (typeof body !== 'string') throw new Error('Telemetry body must be JSON object or JSON string');
  return JSON.parse(body);
}

export function normalizeSensorEvent(body, source = 'generic') {
  const x = parseMaybeJson(body);
  if (source === 'suricata') return { source:'suricata', sensor:x.sensor || 'suricata', timestamp:x.timestamp, sourceIp:x.src_ip, sourcePort:x.src_port, destinationIp:x.dest_ip, destinationPort:x.dest_port, protocol:x.proto, service:x.app_proto, eventType:x.event_type || x.alert?.signature || 'ids_alert', message:x.alert?.signature || x.alert?.category, knownMalicious:x.alert?.severity >= 3, payload:x.http?.hostname || x.dns?.rrname };
  if (source === 'zeek') return { source:'zeek', sensor:x.sensor || 'zeek', timestamp:x.ts ? new Date(Number(x.ts)*1000).toISOString() : x.timestamp, sourceIp:x.id?.orig_h || x.src, sourcePort:x.id?.orig_p || x.src_port, destinationIp:x.id?.resp_h || x.dst, destinationPort:x.id?.resp_p || x.dst_port, protocol:x.proto, service:x.service, eventType:x.eventType || 'network_observation', message:x.note || x.msg };
  if (source === 'cowrie') return { source:'cowrie', sensor:x.sensor || 'cowrie', timestamp:x.timestamp, sourceIp:x.src_ip || x.src_ip_address, sourcePort:x.src_port, destinationPort:x.dst_port || 22, protocol:x.protocol || 'tcp', service:x.service || 'ssh', eventType:x.eventid || x.eventType || 'ssh_event', username:x.username, password:x.password, message:x.message || x.input, payload:x.input };
  if (source === 'dionaea') return { source:'dionaea', sensor:x.sensor || 'dionaea', timestamp:x.timestamp, sourceIp:x.remote_host || x.src_ip, sourcePort:x.remote_port || x.src_port, destinationPort:x.local_port || x.dst_port, protocol:x.protocol || 'tcp', service:x.service, eventType:x.event_type || 'network_observation', message:x.message, payload:x.payload };
  return { ...x, source:x.source || source };
}

export function ingestSensorEvent(body, source='generic', meta={}) { return ingestThreatEvent(normalizeSensorEvent(body, source), { ...meta, source }); }
export function ingestSensorBatch(body, source='generic', meta={}) { const data=parseMaybeJson(body); const arr=Array.isArray(data)?data:(data.events || data.records); if(!Array.isArray(arr)) throw new Error('Telemetry batch requires an array or {events:[]}'); return ingestBatch(arr.map(x=>normalizeSensorEvent(x, source)), { ...meta, source }); }
