import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { loadS39, root } from './load.mjs';

const S39 = loadS39();
const shamir39 = S39.schemes.shamir39;

// Reference implementation (vendored from the user's shamir39-cli, itself the
// iancoleman/shamir39 implementation, MIT). Used as an interop oracle only.
globalThis.module = { exports: {} }; // CommonJS shim for the reference file's export line
globalThis.window = globalThis; // the reference's RNG setup expects a browser window
(0, eval)(readFileSync(path.join(root, 'vectors/shamir39-reference.js'), 'utf8'));
delete globalThis.module;
const reference = new globalThis.Shamir39();
const WORDLIST = [...S39.bip39Words];

const MNEMONIC_12 = ('abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon about').split(' ');
const MNEMONIC_24 = ('legal winner thank year wave sausage worth useful legal winner ' +
  'thank year wave sausage worth useful legal winner thank year ' +
  'wave sausage worth title').split(' ');

function testRng(seedByte = 5) {
  let s = seedByte;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      s = (s * 1103515245 + 12345) & 0x7fffffff;
      out[i] = (s >> 7) & 0xff;
    }
    return out;
  };
}

test('interop: reference split -> our combine', () => {
  for (const [mnemonic, m, n] of [[MNEMONIC_12, 2, 3], [MNEMONIC_12, 3, 5], [MNEMONIC_24, 4, 6]]) {
    const res = reference.split(mnemonic, WORDLIST, m, n);
    assert.ok(!res.error, res.error);
    const shares = res.mnemonics.map((words) => words.join(' '));
    // threshold-sized subset, deliberately out of order
    const subset = shares.slice(n - m).reverse();
    const combined = shamir39.combine({ mnemonics: subset });
    assert.equal(combined.words.join(' '), mnemonic.join(' '), `${m}-of-${n}`);
    assert.equal(combined.memberThreshold, m);
  }
});

test('interop: our split -> reference combine', () => {
  for (const [mnemonic, m, n] of [[MNEMONIC_12, 2, 3], [MNEMONIC_24, 3, 5]]) {
    const shares = shamir39.split({ words: mnemonic, threshold: m, count: n, randomBytes: testRng(9) });
    assert.equal(shares.length, n);
    const subset = shares.slice(0, m).map((s) => s.split(' '));
    const res = reference.combine(subset, WORDLIST);
    assert.ok(!res.error, res.error);
    assert.equal(res.mnemonic.join(' '), mnemonic.join(' '), `${m}-of-${n}`);
  }
});

test('roundtrip with any subset and duplicate shares', () => {
  const shares = shamir39.split({ words: MNEMONIC_24, threshold: 3, count: 5, randomBytes: testRng(2) });
  for (const pick of [[0, 1, 2], [4, 2, 0], [1, 3, 4]]) {
    const combined = shamir39.combine({ mnemonics: pick.map((i) => shares[i]) });
    assert.equal(combined.words.join(' '), MNEMONIC_24.join(' '));
  }
  // duplicate of the same share does not count towards the threshold
  assert.throws(
    () => shamir39.combine({ mnemonics: [shares[0], shares[0], shares[1]] }),
    /not enough/
  );
});

test('not enough shares / inconsistent thresholds rejected', () => {
  const shares = shamir39.split({ words: MNEMONIC_12, threshold: 3, count: 4, randomBytes: testRng(3) });
  assert.throws(() => shamir39.combine({ mnemonics: shares.slice(0, 2) }), /not enough/);
  const other = shamir39.split({ words: MNEMONIC_12, threshold: 2, count: 2, randomBytes: testRng(4) });
  assert.throws(() => shamir39.combine({ mnemonics: [shares[0], other[0]] }), /disagree/);
});

test('multi-word parameter encoding (spec example: M=35, O=10 -> "lottery ask")', () => {
  const res = reference.split(MNEMONIC_12, WORDLIST, 35, 36);
  assert.ok(!res.error, res.error);
  const ourShares = shamir39.split({ words: MNEMONIC_12, threshold: 35, count: 36, randomBytes: testRng(6) });
  // share with order 10 must carry the spec's documented parameter words
  assert.deepEqual(ourShares[10].split(' ').slice(1, 3), ['lottery', 'ask']);
  assert.deepEqual(res.mnemonics[10].slice(1, 3), ['lottery', 'ask']);
  // and a threshold-sized set still recovers on both sides
  const combined = shamir39.combine({ mnemonics: ourShares.slice(0, 35) });
  assert.equal(combined.words.join(' '), MNEMONIC_12.join(' '));
});

test('inspect and scheme detection', async () => {
  const shares = shamir39.split({ words: MNEMONIC_12, threshold: 2, count: 3, randomBytes: testRng(7) });
  const info = shamir39.inspect(shares[1]);
  assert.equal(info.scheme, 'shamir39');
  assert.equal(info.memberThreshold, 2);
  assert.equal(info.memberIndex, 1);

  assert.equal(S39.schemes.detect(shares[0]), 'shamir39');
  const slipShares = await S39.schemes.slip39.split({
    masterSecret: new Uint8Array(16).fill(9),
    threshold: 2,
    count: 2,
    randomBytes: testRng(8),
  });
  assert.equal(S39.schemes.detect(slipShares[0]), 'slip39');
  assert.equal(S39.schemes.detect('completely unrelated words here'), null);
  // a BIP39 mnemonic is neither (BIP39 words are not all SLIP39 words)
  assert.equal(S39.schemes.detect(MNEMONIC_12.join(' ')), null);
});

test('shamir39 shares of the BIP39 test mnemonic remain BIP39-checksum-valid after roundtrip', async () => {
  const shares = shamir39.split({ words: MNEMONIC_24, threshold: 2, count: 2, randomBytes: testRng(11) });
  const { words } = shamir39.combine({ mnemonics: shares });
  assert.equal(await S39.bip39.validateMnemonic(words), true);
});
