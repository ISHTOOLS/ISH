/** Local threat-intelligence feed loader. No remote feed is assumed. */
import fs from 'node:fs';
import { readJson, writeJson } from './store.js';
const FILE='threat-feed.json';
export function getLocalFeed(){ return readJson(FILE,{entries:{},source:'NOT_CONFIGURED',updatedAt:null}); }
export function setLocalFeed(entries, source='operator-import'){ if(!entries || typeof entries!=='object') throw new Error('entries object required'); const data={entries,source:String(source).slice(0,256),updatedAt:new Date().toISOString()}; writeJson(FILE,data); return {count:Object.keys(entries).length,source:data.source,updatedAt:data.updatedAt}; }
export function importFeedFile(filePath, source='file-import'){ if(!fs.existsSync(filePath)) throw new Error('Feed file not found'); const parsed=JSON.parse(fs.readFileSync(filePath,'utf8')); return setLocalFeed(parsed.entries || parsed, source); }
