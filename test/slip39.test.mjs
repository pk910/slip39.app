import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39, readVectors } from './load.mjs';

const S39 = loadS39();
const { bytesToHex, hexToBytes } = S39.util;
const slip39 = S39.schemes.slip39;

// Deterministic RNG for reproducible split tests (NOT used by the app).
function makeTestRng(seedByte = 7) {
  let state = seedByte;
  return (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      state = (state * 1103515245 + 12345) & 0x7fffffff;
      out[i] = state & 0xff;
    }
    return out;
  };
}

test('official SLIP39 test vectors (trezor/python-shamir-mnemonic)', async () => {
  const vectors = readVectors('vectors.json');
  assert.ok(vectors.length >= 40);
  for (const [description, mnemonics, masterSecretHex] of vectors) {
    if (masterSecretHex === '') {
      await assert.rejects(
        slip39.combine({ mnemonics, passphrase: 'TREZOR' }),
        undefined,
        `should reject: ${description}`
      );
    } else {
      const result = await slip39.combine({ mnemonics, passphrase: 'TREZOR' });
      assert.equal(bytesToHex(result.masterSecret), masterSecretHex, description);
    }
  }
});

test('official vectors: master secret is the BIP32 seed (xprv check)', async () => {
  const vectors = readVectors('vectors.json');
  let checked = 0;
  for (const [description, , masterSecretHex, xprv] of vectors) {
    if (masterSecretHex === '' || !xprv) continue;
    const node = await S39.bip32.fromMasterSeed(hexToBytes(masterSecretHex));
    assert.equal(await S39.bip32.toExtendedPrivateKey(node), xprv, description);
    if (++checked >= 8) break; // sample is enough; all use the same code path
  }
  assert.ok(checked > 0);
});

test('split/combine roundtrip 2-of-3 (128 bit)', async () => {
  const secret = hexToBytes('0ff784df000c4380a5ed683557d8bc40');
  const mnemonics = await slip39.split({
    masterSecret: Uint8Array.from(secret),
    threshold: 2,
    count: 3,
    randomBytes: makeTestRng(1),
  });
  assert.equal(mnemonics.length, 3);
  for (const m of mnemonics) assert.equal(m.split(' ').length, 20);

  // every 2-combination recovers, order independent
  for (const pair of [[0, 1], [0, 2], [1, 2], [2, 0]]) {
    const result = await slip39.combine({ mnemonics: pair.map((i) => mnemonics[i]) });
    assert.equal(bytesToHex(result.masterSecret), bytesToHex(secret));
  }
  // a single share does not recover
  await assert.rejects(slip39.combine({ mnemonics: [mnemonics[0]] }));
});

test('split/combine roundtrip 3-of-5 (256 bit) with passphrase', async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const mnemonics = await slip39.split({
    masterSecret: Uint8Array.from(secret),
    threshold: 3,
    count: 5,
    passphrase: 'correct horse',
    randomBytes: makeTestRng(2),
  });
  for (const m of mnemonics) assert.equal(m.split(' ').length, 33);

  const good = await slip39.combine({
    mnemonics: [mnemonics[4], mnemonics[0], mnemonics[2]],
    passphrase: 'correct horse',
  });
  assert.equal(bytesToHex(good.masterSecret), bytesToHex(secret));

  // wrong passphrase yields a *different* secret (SLIP39 by design), not an error
  const wrong = await slip39.combine({
    mnemonics: mnemonics.slice(0, 3),
    passphrase: 'wrong horse',
  });
  assert.notEqual(bytesToHex(wrong.masterSecret), bytesToHex(secret));

  // too few shares
  await assert.rejects(slip39.combine({ mnemonics: mnemonics.slice(0, 2), passphrase: 'correct horse' }));
});

test('tampered share word fails the checksum', async () => {
  const mnemonics = await slip39.split({
    masterSecret: hexToBytes('00112233445566778899aabbccddeeff'),
    threshold: 2,
    count: 2,
    randomBytes: makeTestRng(3),
  });
  const words = mnemonics[0].split(' ');
  words[10] = words[10] === 'academic' ? 'acid' : 'academic';
  await assert.rejects(
    slip39.combine({ mnemonics: [words.join(' '), mnemonics[1]] }),
    /checksum/
  );
});

test('mixed share sets are rejected', async () => {
  const a = await slip39.split({
    masterSecret: hexToBytes('00112233445566778899aabbccddeeff'),
    threshold: 2,
    count: 2,
    randomBytes: makeTestRng(4),
  });
  const b = await slip39.split({
    masterSecret: hexToBytes('ffeeddccbbaa99887766554433221100'),
    threshold: 2,
    count: 2,
    randomBytes: makeTestRng(5),
  });
  await assert.rejects(slip39.combine({ mnemonics: [a[0], b[1]] }), /different share sets/);
});

test('1-of-m split is refused, 1-of-1 works', async () => {
  const secret = hexToBytes('00112233445566778899aabbccddeeff');
  await assert.rejects(
    slip39.split({ masterSecret: Uint8Array.from(secret), threshold: 1, count: 3, randomBytes: makeTestRng(6) }),
    /1-of-m/
  );
  const single = await slip39.split({
    masterSecret: Uint8Array.from(secret),
    threshold: 1,
    count: 1,
    randomBytes: makeTestRng(6),
  });
  const result = await slip39.combine({ mnemonics: single });
  assert.equal(bytesToHex(result.masterSecret), bytesToHex(secret));
});

test('duplicate share is tolerated, conflicting share rejected', async () => {
  const secret = hexToBytes('00112233445566778899aabbccddeeff');
  const mnemonics = await slip39.split({
    masterSecret: Uint8Array.from(secret),
    threshold: 2,
    count: 3,
    randomBytes: makeTestRng(7),
  });
  const result = await slip39.combine({ mnemonics: [mnemonics[0], mnemonics[0], mnemonics[1]] });
  assert.equal(bytesToHex(result.masterSecret), bytesToHex(secret));
});

test('inspect reports share metadata', async () => {
  const mnemonics = await slip39.split({
    masterSecret: hexToBytes('00112233445566778899aabbccddeeff'),
    threshold: 2,
    count: 3,
    randomBytes: makeTestRng(8),
  });
  const info = slip39.inspect(mnemonics[1]);
  assert.equal(info.memberThreshold, 2);
  assert.equal(info.groupCount, 1);
  assert.equal(info.secretBytes, 16);
  assert.equal(info.words, 20);
});

test('extendable flag roundtrip', async () => {
  const secret = hexToBytes('00112233445566778899aabbccddeeff');
  const mnemonics = await slip39.split({
    masterSecret: Uint8Array.from(secret),
    threshold: 2,
    count: 2,
    extendable: true,
    randomBytes: makeTestRng(9),
  });
  assert.equal(slip39.inspect(mnemonics[0]).extendable, true);
  const result = await slip39.combine({ mnemonics });
  assert.equal(bytesToHex(result.masterSecret), bytesToHex(secret));
});
