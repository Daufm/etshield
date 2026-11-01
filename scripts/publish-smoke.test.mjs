import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspacePatterns = ['packages', 'apps'];
const npm = process.env.npm_execpath ?? 'npm';

function packageJson(packageRoot) {
  return JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
}

function workspacePackages() {
  return workspacePatterns.flatMap((directory) =>
    readdirSync(join(root, directory), { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => {
        const packageRoot = join(root, directory, entry.name);
        return { root: packageRoot, manifest: packageJson(packageRoot) };
      }),
  );
}

function dependencyNames(manifest) {
  return Object.keys({
    ...manifest.dependencies,
    ...manifest.optionalDependencies,
    ...manifest.peerDependencies,
  });
}

test('workspace package dependencies do not require private packages at publish time', () => {
  const packages = workspacePackages();
  const byName = new Map(packages.map((workspace) => [workspace.manifest.name, workspace]));

  for (const workspace of packages) {
    if (workspace.manifest.private === true) continue;
    const bundled = new Set(
      workspace.manifest.bundledDependencies ?? workspace.manifest.bundleDependencies ?? [],
    );
    for (const dependencyName of dependencyNames(workspace.manifest)) {
      const dependency = byName.get(dependencyName);
      if (dependency === undefined) continue;
      assert.equal(
        dependency.manifest.private === true && !bundled.has(dependencyName),
        false,
        `${workspace.manifest.name} depends on private workspace package ${dependencyName}`,
      );
    }
  }
});

// Informational diagnostic: --offline with an empty cache fails for any registry dependency.
test('offline install diagnostic', () => {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'ethioshield-publish-smoke-'));
  const cacheDirectory = join(temporaryDirectory, 'cache');
  try {
    try {
      writeFileSync(join(temporaryDirectory, 'package.json'), '{"private":true}\n');
      const tarball = execFileSync(npm, ['pack', '--pack-destination', temporaryDirectory], {
        cwd: join(root, 'packages/sdk-node'),
        encoding: 'utf8',
      })
        .trim()
        .split('\n')
        .at(-1);
      assert.ok(tarball);
      execFileSync(
        npm,
        [
          'install',
          '--cache',
          cacheDirectory,
          '--offline',
          '--legacy-peer-deps',
          '--no-audit',
          '--no-fund',
          join(temporaryDirectory, tarball),
        ],
        { cwd: temporaryDirectory, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
      );
      console.log('offline install diagnostic: install succeeded');
    } catch (error) {
      const text = `${error.stdout ?? ''}\n${error.stderr ?? ''}`.replaceAll('%2f', '/');
      console.log(`offline install diagnostic: ${text}`);
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});
