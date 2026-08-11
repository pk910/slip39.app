# slip39.app

> https://github.com/pk910/slip39.app · deployed at https://slip39.app

Offline browser tool to **split a BIP39 mnemonic into Shamir shares** — SLIP-0039 or the
legacy Shamir39 format — and to **recover it** from a quorum of shares. Runs 100% locally
— as a double-clickable single HTML file or hosted at slip39.app. No frameworks, no npm
dependencies, no network access.

## Features

- **Generate** a fresh 12- or 24-word BIP39 mnemonic. Randomness = OS CSPRNG
  (`crypto.getRandomValues`) XOR-mixed with ≥1024 bits of user entropy collected from
  mouse/touch movement (position, position product à la bitaddress.org, µs timing —
  continuously absorbed into a SHA-256 pool; generation is blocked until the target is
  reached). Neither source alone determines the output, so a weak/backdoored source is
  masked by the other.
- **Split** a 12/15/18/21/24-word mnemonic into `n`-of-`m` shares (max 16, single group)
  in either format: **SLIP-0039** (recommended; per-share RS1024 checksum, cross-share
  digest, optional passphrase/iteration exponent/extendable flag, Trezor-compatible) or
  **Shamir39** (legacy; wire-compatible with iancoleman.github.io/shamir39 and
  pk910/shamir39-cli). After splitting, the app recombines a random `n`-subset
  internally and verifies it reproduces the exact input (self-check).
- **Recover** a mnemonic from shares (one per line) — the share format is
  **auto-detected**. SLIP-0039 recovery checks per-share RS1024 checksums (live, as you
  type), the cross-share digest, and rebuilds the BIP39 mnemonic. Shamir39 shares carry
  no integrity data, so the BIP39 checksum of the result is verified and reported
  instead.
- **Info tab**: derives from an explicit mnemonic field (prefilled by
  generate/split/recover, or paste any mnemonic) with an optional BIP39 passphrase.
  Shows account extended public keys (xpub/ypub/zpub per SLIP-0132) and the first two
  receiving addresses for common paths — BTC BIP44 (P2PKH), BIP49 (P2SH-P2WPKH), BIP84
  (P2WPKH), Ethereum BIP44 (EIP-55), TRON BIP44 (TRC-20 Base58Check) and Solana
  (SLIP-0010 ed25519, Phantom-style paths). A **custom path resolver** takes any
  derivation path plus an address type and returns the extended public key at that path
  and the addresses for the path and its first two children (hardened for ed25519).
- **Security panel**: connection status (with "go offline" warning), runtime-poisoning
  checks of browser built-ins, and a **wipe-session** action that overwrites all secret
  buffers and clears the DOM.

## Security model

**No supply chain.** There are zero runtime and zero build-time npm dependencies. The
heavy cryptography (SHA-256/512, HMAC, PBKDF2) uses the browser's native WebCrypto,
which a package manager cannot swap out. The remaining primitives are vendored into
`js/lib/` as small, readable classic scripts, each with a provenance header:

| File | Origin |
|---|---|
| `js/lib/keccak256.js` | implemented from the Keccak reference spec; round constants/rotations are *computed*, not transcribed |
| `js/lib/ripemd160.js` | ported from `@noble/hashes` 2.3.0 (`legacy.js`) |
| `js/lib/secp256k1.js` | minimal (pubkey derivation only), parameters from SEC 2 v2 |
| `js/lib/ed25519.js` | public-key derivation from RFC 8032 (curve constant computed, not transcribed) |
| `js/lib/slip10.js` | SLIP-0010 ed25519 hardened derivation (Solana) |
| `js/lib/bech32.js` | from the BIP-0173 reference implementation |
| `js/lib/base58.js` | from the Base58Check spec |
| `js/lib/bip39.js`, `js/lib/bip32.js` | implemented from the BIPs |
| `js/schemes/slip39/*` | implemented from SLIP-0039 |

**Everything is pinned by official test vectors** (`npm test`, needs only Node ≥ 20):
all 45 Trezor SLIP-0039 vectors, the Trezor BIP39 vectors, the BIP32 spec vectors
(including the leading-zero edge cases), BIP84/EIP-55 address vectors, RIPEMD-160
official vectors, xpub/ypub/zpub vectors validated against the BIP84 spec, the official
SLIP-0010 ed25519 test vectors, RFC 8032 ed25519 key vectors, Solana derivations
cross-referenced against ed25519-hd-key/noble-ed25519, the documented TRON Base58Check
pair, and multi-block Keccak/RIPEMD cross-references generated once from audited
noble-hashes.
The Shamir39 implementation is tested for **bidirectional interoperability** against
the vendored reference implementation (`vectors/shamir39-reference.js`, from
pk910/shamir39-cli, itself the iancoleman/shamir39 code).

**No network.** The page ships a strict CSP:
`default-src 'none'; script-src <hash>; style-src <hash>; connect-src 'none'; …` —
`fetch`, XHR, WebSockets, beacons, external images/fonts/scripts are all blocked by the
browser itself. Limits to be aware of: a `<meta>` CSP cannot stop the *user* from
navigating away, and `frame-ancestors` only works as an HTTP header (included in
`dist/_headers`). The app makes zero outbound references either way; still, the UI
recommends going physically offline while secrets are on screen, because no in-page
mechanism can guarantee the absence of side channels on a compromised machine.

**Script integrity.** `npm run build` produces `dist/index.html` — one self-contained
file whose inline script/style are locked by CSP sha256 hashes, plus `dist/SHA256SUMS`.
Verify a downloaded release before use:

```sh
sha256sum index.html   # compare against SHA256SUMS from the repository
```

**Runtime poisoning checks & hardening.** All crypto entry points
(`crypto.getRandomValues`, the `crypto.subtle` methods) are **captured and bound at
load time** by the first scripts — swapping the globals later has no effect, and a
dedicated check flags when the live globals no longer match the captured references.
On load the app additionally verifies that the relevant built-ins are native code, that
RNG output is sane and that no service worker is registered; the result shows as a
✓/✗ status in the footer (details in a modal), plus a red banner on failure. As soon as
the last script finishes, the entire `S39` namespace tree is **deep-frozen** (objects,
functions, prototypes, nested tables — cycle-safe), and the wordlist indexes are
closure-backed frozen lookups rather than `Map`s, because `Object.freeze` cannot
protect Map internals. (All best-effort: code that ran *before* the app — e.g. a
malicious extension at `document_start` — can in principle defeat any in-page defense.
For real funds, use a clean browser profile without extensions, or an air-gapped
machine.)

**Privacy blur with decoys.** Secrets — mnemonic inputs, share fields and cards, and
recovered words — are blurred by default and reveal individually on hover, focus or tap
(touch devices get an explicit tap-to-reveal, since mobile hover/focus semantics are
unreliable); a "hover/tap to view" caption marks them, and a header toggle disables the
feature. Crucially, a blurred area does not display the real content: the DOM shows
**same-shape garbage** (random words from the matching wordlist), so de-blurring a
screenshot or recording — including with AI deconvolution — yields decoys, not secrets.
Derived addresses and extended public keys are deliberately not blurred (they cannot
spend funds). Honest limitation: no web page can prevent OS-level screenshots of
content you have deliberately revealed at that moment.

**Secure erase.** All secret bytes live in `Uint8Array`s registered with a wipe
registry; "Wipe session" overwrites them (random, then 0xFF, then zeros), clears every
input field and removes rendered secrets from the DOM. A wipe also runs automatically on
page hide. Honest limitation: JavaScript strings are immutable and the GC may hold stale
copies — after handling real keys, wipe, **close the tab**, and ideally reboot.
Clipboard use is discouraged in-UI (other apps can read it).

## Running

- **Simplest**: `npm run build`, then double-click `dist/index.html` (works from
  `file://`), ideally on an offline machine.
- **Dev**: serve the repo root (`npm run serve` → http://localhost:8039) — the multi-file
  source loads as-is; there is no build/transpile step, what you audit is what runs.
- **Tests**: `npm test` (Node's built-in runner, no installs).

## Releases & deploying to slip39.app

**Security model: GitHub cannot deploy production.** The repository holds no Cloudflare
credentials — a compromised GitHub account can at worst publish a tampered release
asset, never touch the live site. The second factor is the Cloudflare account itself
(its own login + 2FA), used only from a maintainer's machine.

**Release (automated, GitHub Actions):** pushing a tag `vX.Y.Z` runs the full vector
test suite, builds with the version and the tag's commit date baked in
(`node scripts/build-release.mjs --version vX.Y.Z --date <commit-date>` — fully
deterministic: same tag + flags ⇒ byte-identical output), and publishes a GitHub
Release with `index.html`, `SHA256SUMS` and `_headers`. Pushes to `main` only run CI;
nothing deploys.

**Hosting (Cloudflare Pages, git-integrated):** the Pages project builds every branch
as a *preview* on `*.slip39-app.pages.dev` (dev builds, commit-stamped), and uses the
`release` branch as its production branch — but with **automatic production
deployments disabled**. Tagging `vX.Y.Z` makes the release workflow fast-forward
`release` to the tag, which only *stages* the release; shipping it to slip39.app is a
one-click manual approval in the Cloudflare dashboard, behind the Cloudflare login and
its 2FA. Before approving, glance that the staged commit SHA equals the tag
(`git rev-parse vX.Y.Z` or the commit page on GitHub) — that closes the loop against a
compromised GitHub account pushing something else to `release`.

Cloudflare build command (Settings → Build):

```sh
if [ "$CF_PAGES_BRANCH" = "release" ]; then node scripts/build-release.mjs --version "$(cat VERSION)" --date "$(git log -1 --format=%cs)"; else node scripts/build-release.mjs --commit "$CF_PAGES_COMMIT_SHA"; fi
```

Build output directory: `dist`. The generated `dist/_headers` applies the CSP +
security headers on every deployment.

**Release flow:** bump `VERSION` (must equal the tag — the workflow enforces it),
commit, `git tag vX.Y.Z && git push origin main vX.Y.Z`, wait for the GitHub release,
then approve the production deployment in the Cloudflare dashboard.

Recommended extras on GitHub: require signed tags, tag protection for `v*`, 2FA —
layers on top; the load-bearing wall is that production needs the Cloudflare login.
For self-hosting with nginx instead, mirror the headers from `dist/_headers` via
`add_header` (the exact CSP hashes are printed by `npm run build`).

## Notes on SLIP-0039 semantics

- A **wrong SLIP39 passphrase does not produce an error** — it produces a different,
  valid-looking mnemonic (plausible deniability is part of the spec). Verify recovered
  wallets via the derived addresses.
- **1-of-m splits are forbidden** by the spec (each share alone would reveal the
  secret); the UI enforces `n ≥ 2` when `m > 1`. Use multiple copies of a 1-of-1 share
  if that is really what you want.
- Shares are generated non-extendable by default for maximum compatibility; the
  extendable-backup flag is available under Advanced options, and both kinds are
  accepted on recovery.
- The word lists differ on purpose: BIP39 mnemonics use the 2048-word BIP39 list,
  SLIP39 shares the 1024-word SLIP39 list. Shamir39 shares use the BIP39 list prefixed
  with the version token `shamir39-p1`.
- **Shamir39 is a legacy format**: no checksums, no digest, no passphrase. A wrong or
  mistyped share is only caught if the combined result fails the BIP39 checksum (and a
  wrong-but-checksum-passing result is possible with probability ~2^-4 to 2^-8). Prefer
  SLIP-0039 for new backups; Shamir39 support exists for recovering old share sets and
  interop with existing tools.

## Structure

```
index.html            app shell (dev: multi-file; release inlines everything)
css/app.css           hand-written vanilla CSS
js/lib/               vendored crypto primitives + BIP39/BIP32 (see provenance table)
js/schemes/slip39/    SLIP-0039: GF(256) Shamir, RS1024, Feistel cipher, share codec
js/schemes/shamir39/  Shamir39 (legacy): GF(2^11) Shamir, param/word codec, autodetect
js/app/               entropy collector, security/wipe, wallet derivation, UI
scripts/build-release.mjs  zero-dependency single-file release builder
test/                 node --test suites pinned to official vectors
vectors/              official + generated test vectors, vendored shamir39 reference
```

Both schemes implement the same `split/combine/inspect` interface;
`S39.schemes.detect()` picks the right one from a pasted share.

## Disclaimer

This tool handles keys that control real funds. Audit the source, verify the file hash,
run it on an offline machine, and test recovery with throwaway mnemonics before trusting
it with anything valuable.
