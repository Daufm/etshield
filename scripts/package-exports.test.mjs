import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const packages = ['security-contracts', 'sdk-node'];

for (const packageName of packages) {
  test(`${packageName} exports its built ESM entry point`, async () => {
    const packageRoot = resolve(root, 'packages', packageName);
    const packageJson = JSON.parse(readFileSync(resolve(packageRoot, 'package.json'), 'utf8'));
    const entry = packageJson.exports['.'];

    assert.equal(typeof entry.import, 'string');
    assert.equal(typeof entry.types, 'string');
    assert.equal(existsSync(resolve(packageRoot, entry.import)), true);
    assert.equal(existsSync(resolve(packageRoot, entry.types)), true);

    const module = await import(`${packageRoot}/${entry.import}`);
    assert.equal(typeof module, 'object');
  });
}
