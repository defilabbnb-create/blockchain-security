import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
export async function runtimeFingerprint() {
  const files = ['package.json', 'package-lock.json', 'flare-scan/chains.json'];
  async function visit(dir) {
    for (const entry of await readdir(join(root, dir), { withFileTypes: true })) {
      if (entry.isDirectory() && entry.name !== '__pycache__') await visit(join(dir, entry.name));
      else if (entry.isFile() && /\.(?:js|mjs|cjs|css|html|py|json)$/.test(entry.name)) files.push(join(dir, entry.name));
    }
  }
  await Promise.all(['src', 'web', 'scripts', 'config'].map(visit));
  const hash = createHash('sha256');
  for (const file of files.sort()) hash.update(file).update('\0').update(await readFile(join(root, file))).update('\0');
  return hash.digest('hex');
}
