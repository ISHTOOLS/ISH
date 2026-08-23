import fs from 'fs';
import path from 'path';

const configuredDataDir = process.env.ISHV4_DATA_DIR || 'data';

const DATA_DIR = path.isAbsolute(configuredDataDir)
  ? configuredDataDir
  : path.resolve(process.cwd(), configuredDataDir);

export function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

export function readJson(filename, fallback) {
  ensureDataDir();

  const p = path.join(DATA_DIR, filename);

  if (!fs.existsSync(p)) {
    return fallback;
  }

  try {
    return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch {
    return fallback;
  }
}

// Atomic write: write to temp file then rename,
// so a crash mid-write never corrupts the real file.
export function writeJson(filename, data) {
  ensureDataDir();

  const p = path.join(DATA_DIR, filename);
  const tmp = `${p}.tmp-${process.pid}-${Date.now()}`;

  fs.writeFileSync(
    tmp,
    JSON.stringify(data, null, 2),
    { mode: 0o600 }
  );

  fs.renameSync(tmp, p);
}

export function appendLine(filename, line) {
  ensureDataDir();

  const p = path.join(DATA_DIR, filename);

  fs.appendFileSync(
    p,
    line + '\n',
    { mode: 0o600 }
  );
}

export function readLines(filename) {
  ensureDataDir();

  const p = path.join(DATA_DIR, filename);

  if (!fs.existsSync(p)) {
    return [];
  }

  return fs
    .readFileSync(p, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function dataFilePath(filename) {
  return path.join(DATA_DIR, filename);
}