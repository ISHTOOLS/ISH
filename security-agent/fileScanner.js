import fs from 'node:fs'; import crypto from 'node:crypto';
export function hashFile(filePath) { return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex'); }
export function scanFiles(paths=[]) { return paths.slice(0,100).map(filePath=>{try{return {path:String(filePath).slice(0,512),sha256:hashFile(filePath),readable:true};}catch{return {path:String(filePath).slice(0,512),readable:false};}}); }
