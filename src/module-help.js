import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_DIR = __dirname;

/**
 * Real runtime module documentation system. Does NOT require a separate
 * "#[doc]" annotation syntax to invent and maintain - it parses the
 * REAL header block comments (/** ... *\/) that already exist at the top
 * of every src/*.js file in this project (see e.g. anomaly-rate-limit.js,
 * raft.js, vault.js). Documentation drifts less when it's read directly
 * from the same comment a developer already has to update to explain
 * a change, instead of a second, separate doc source that's easy to
 * forget.
 */

function extractHeaderComment(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  // Find the FIRST /** ... */ block anywhere near the top of the file
  // (not anchored to position 0 - most files have `import` statements
  // before their documentation header, as ES module syntax requires).
  const match = content.match(/\/\*\*([\s\S]*?)\*\//);
  if (!match) return null;
  return match[1]
    .split('\n')
    .map((l) => l.replace(/^\s*\*\s?/, ''))
    .join('\n')
    .trim();
}

function extractExportedFunctions(filePath) {
  const content = fs.readFileSync(filePath, 'utf-8');
  const matches = [...content.matchAll(/export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g)];
  const constMatches = [...content.matchAll(/export\s+const\s+(\w+)\s*=/g)];
  return [
    ...matches.map((m) => ({ name: m[1], params: m[2].trim(), kind: 'function' })),
    ...constMatches.map((m) => ({ name: m[1], params: '', kind: 'const' })),
  ];
}

export function listModules() {
  const files = fs.readdirSync(SRC_DIR).filter((f) => f.endsWith('.js'));
  return files.map((f) => {
    const filePath = path.join(SRC_DIR, f);
    const header = extractHeaderComment(filePath);
    return {
      module: f.replace('.js', ''),
      summary: header ? header.split('\n')[0] : '(dokümantasyon yorumu bulunamadı)',
      hasDocs: !!header,
    };
  });
}

export function getModuleHelp(moduleName) {
  const filePath = path.join(SRC_DIR, `${moduleName}.js`);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Modül bulunamadı: "${moduleName}". Mevcut modüller için GET /api/help kullanın.`);
  }
  return {
    module: moduleName,
    documentation: extractHeaderComment(filePath) || '(bu modül için üst-seviye dokümantasyon yorumu yok)',
    exportedFunctions: extractExportedFunctions(filePath),
  };
}
