// Release builder — Node built-ins only, no npm dependencies.
//
// Produces:
//   dist/index.html   single self-contained file (CSS + all JS inlined),
//                     CSP locked to the sha256 hashes of the inlined blocks
//   dist/SHA256SUMS   hash of the release file + every source file
//   dist/_headers     CSP/security headers for static hosts serving the file
//
// The single-file build works from file:// (double-click), from any static
// host, and its integrity is verifiable with one `sha256sum` invocation.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Usage: node scripts/build-release.mjs [--version vX.Y.Z] [--date YYYY-MM-DD]
// With both flags the output is fully deterministic: building the same tag
// with the same flags yields byte-identical files (the basis for verifying a
// published release by rebuilding it locally). CI passes the tag name and the
// tag's commit date; without flags this is a "dev build" stamped with today.
const argv = process.argv.slice(2);
const argValue = (name) => {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : null;
};
const version = argValue('--version');
const buildDate = argValue('--date') || new Date().toISOString().slice(0, 10);
const commit = argValue('--commit'); // dev builds: stamp the commit for traceability
if (version && !/^v?\d+\.\d+\.\d+(-[\w.]+)?$/.test(version)) {
  throw new Error(`implausible version "${version}" — expected e.g. v1.2.0`);
}
const buildLabel = version
  ? `release ${version} (${buildDate})`
  : `dev build ${buildDate}${commit ? ` · ${commit.slice(0, 7)}` : ''}`;

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(path.join(root, p), 'utf8');
const sha256hex = (data) => createHash('sha256').update(data).digest('hex');
const sha256b64 = (data) => createHash('sha256').update(data).digest('base64');

let html = read('index.html');

// collect script sources in document order
const scriptTags = [...html.matchAll(/^\s*<script src="([^"]+)"><\/script>\s*$/gm)];
if (scriptTags.length === 0) throw new Error('no script tags found in index.html');
const scriptFiles = scriptTags.map((m) => m[1]);
const bundledJs =
  '// slip39.app release bundle — concatenation of the audited source files below.\n' +
  scriptFiles
    .map((f) => `// ==== ${f} (sha256 ${sha256hex(read(f))}) ====\n${read(f)}`)
    .join('\n');

// inline stylesheet and script bundle; the CSP hash must cover the exact
// bytes between the tags, so build those strings once and reuse them
const css = read('css/app.css');
const styleCspContent = `\n${css}\n  `;
const scriptCspContent = `\n${bundledJs}\n  `;
html = html.replace(
  /^\s*<link rel="stylesheet" href="css\/app\.css">\s*$/m,
  () => `  <style>${styleCspContent}</style>`
);
html = html.replace(scriptTags[0][0], () => `  <script>${scriptCspContent}</script>`);
for (const m of scriptTags.slice(1)) html = html.replace(m[0], '');

// lock the CSP to the exact hashes of the inlined blocks
const scriptHash = `sha256-${sha256b64(scriptCspContent)}`;
const styleHash = `sha256-${sha256b64(styleCspContent)}`;
const csp = [
  "default-src 'none'",
  `script-src '${scriptHash}'`,
  `style-src '${styleHash}'`,
  "img-src 'self' data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');
html = html.replace(
  /<meta http-equiv="Content-Security-Policy" content="[^"]*">/,
  `<meta http-equiv="Content-Security-Policy" content="${csp}">`
);

// stamp the build
html = html.replace(
  /<span id="app-version">[^<]*<\/span>/,
  `<span id="app-version">${buildLabel} — verify: sha256sum index.html vs SHA256SUMS</span>`
);

mkdirSync(path.join(root, 'dist'), { recursive: true });
writeFileSync(path.join(root, 'dist/index.html'), html);

const releaseHash = sha256hex(readFileSync(path.join(root, 'dist/index.html')));
const sums = [
  `${releaseHash}  index.html`,
  '',
  '# source files bundled into the release:',
  ...scriptFiles.map((f) => `${sha256hex(read(f))}  ${f}`),
  `${sha256hex(css)}  css/app.css`,
  '',
].join('\n');
writeFileSync(path.join(root, 'dist/SHA256SUMS'), sums);

// headers for static hosts (belt & braces on top of the meta CSP)
writeFileSync(
  path.join(root, 'dist/_headers'),
  `/*
  Content-Security-Policy: ${csp}; frame-ancestors 'none'
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()
  Cache-Control: no-store
`
);

console.log(`build                ${buildLabel}`);
console.log(`dist/index.html      ${(html.length / 1024).toFixed(1)} KiB`);
console.log(`sha256               ${releaseHash}`);
console.log(`script CSP hash      ${scriptHash}`);
console.log(`bundled sources      ${scriptFiles.length} js files + app.css`);
