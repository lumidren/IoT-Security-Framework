// Copies the MapLibre GL web worker into public/ so it is served same-origin.
// MapLibre resolves its worker relative to its own module URL, which breaks once
// Next.js bundles the library; the map calls setWorkerUrl() with this path instead.
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const pkgDir = dirname(require.resolve('maplibre-gl/package.json'));
const { version } = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const source = join(pkgDir, 'dist', 'maplibre-gl-worker.mjs');
const targetDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'maplibre');

mkdirSync(targetDir, { recursive: true });
copyFileSync(source, join(targetDir, 'maplibre-gl-worker.mjs'));
console.log(`copied maplibre-gl ${version} worker to public/maplibre/`);
