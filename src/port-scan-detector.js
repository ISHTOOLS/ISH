/** Real port-scan detector: classifies vertical/horizontal scans from observed telemetry. */
import { readJson, writeJson } from './store.js';
const FILE='port-scan-state.json';
const state=readJson(FILE,{windowMs:60000, sources:{}});
function save(){writeJson(FILE,state)}
export function observeConnection({sourceIp,destinationIp,destinationPort,timestamp=Date.now()}){
  if(!sourceIp || destinationPort == null) return null;
  const t=typeof timestamp==='number'?timestamp:Date.parse(timestamp);
  const p=state.sources[sourceIp] ||= {events:[]};
  p.events.push({destinationIp:String(destinationIp||'UNKNOWN'),destinationPort:Number(destinationPort),t});
  p.events=p.events.filter(e=>t-e.t<=state.windowMs);
  const hosts=new Set(p.events.map(e=>e.destinationIp)); const ports=new Set(p.events.map(e=>e.destinationPort));
  const classification=ports.size>=20 && hosts.size<=3?'vertical_scan':hosts.size>=20 && ports.size<=3?'horizontal_scan':(ports.size>=10||hosts.size>=10?'broad_scan':null);
  save();
  return classification?{sourceIp,classification,uniqueHosts:hosts.size,uniquePorts:ports.size,windowMs:state.windowMs}:null;
}
