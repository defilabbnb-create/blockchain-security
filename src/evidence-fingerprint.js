import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// Bind a run to contract sources, fixtures, test vectors and dependency locks.
// Build output is excluded because running the compiler changes it.
export async function evidenceFingerprint(core) {
  const files = [];
  async function visit(dir) {
    for (const entry of await readdir(join(core, dir), { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
    }
  }
  await Promise.all(['contracts', 'test'].map(visit));
  for (const file of ['hardhat.config.js', 'foundry.toml', 'package.json', 'package-lock.json']) {
    try { await readFile(join(core, file)); files.push(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const hash = createHash('sha256');
  for (const file of files.sort()) {
    hash.update(file).update('\0').update(await readFile(join(core, file))).update('\0');
  }
  return hash.digest('hex');
}
