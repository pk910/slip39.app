import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { loadS39, root } from './load.mjs';

// Runs in its own process (node --test isolates test files), so freezing the
// namespace here cannot affect the other suites.
const S39 = loadS39();
(0, eval)(readFileSync(path.join(root, 'js/app/security.js'), 'utf8'));
S39.security.freezeRuntime();

test('deep freeze covers the whole S39 tree', () => {
  assert.ok(Object.isFrozen(S39));
  assert.ok(Object.isFrozen(S39.schemes));
  assert.ok(Object.isFrozen(S39.schemes.slip39), 'nested scheme object');
  assert.ok(Object.isFrozen(S39.wallet.ADDRESS_TYPES), 'nested config table');
  assert.ok(Object.isFrozen(S39.wallet.ADDRESS_TYPES.p2pkh), 'three levels deep');
  assert.ok(Object.isFrozen(S39.bip39Words), 'wordlist array');
  assert.ok(Object.isFrozen(S39.entropy.EntropyCollector), 'class');
  assert.ok(Object.isFrozen(S39.entropy.EntropyCollector.prototype), 'class prototype');

  // strict-mode writes to frozen objects throw
  assert.throws(() => { S39.keccak256 = () => new Uint8Array(32); }, TypeError);
  assert.throws(() => { S39.schemes.slip39.combine = null; }, TypeError);
  assert.throws(() => { S39.bip39WordsIndex.get = () => 0; }, TypeError);
});

test('wordlist indexes are closure-backed and tamper-proof', () => {
  // lookups behave like the old Maps
  assert.equal(S39.bip39WordsIndex.get('abandon'), 0);
  assert.equal(S39.bip39WordsIndex.has('abandon'), true);
  assert.equal(S39.bip39WordsIndex.has('notaword'), false);
  assert.equal(S39.bip39WordsIndex.get('notaword'), undefined);
  assert.equal(S39.slip39WordsIndex.get('academic'), 0);
  // no mutation surface: the index object is frozen and the backing store
  // is closure-private (unlike a Map, whose .set survives Object.freeze)
  assert.equal(typeof S39.bip39WordsIndex.set, 'undefined');
});

test('everything still works after the freeze', async () => {
  const entropy = S39.util.hexToBytes('00112233445566778899aabbccddeeff');
  const shares = await S39.schemes.slip39.split({
    masterSecret: Uint8Array.from(entropy),
    threshold: 2,
    count: 3,
  });
  const combined = await S39.schemes.slip39.combine({ mnemonics: shares.slice(1) });
  assert.deepEqual(Array.from(combined.masterSecret), Array.from(entropy));

  const s39shares = S39.schemes.shamir39.split({
    words: (await S39.bip39.entropyToMnemonic(entropy)),
    threshold: 2,
    count: 2,
  });
  assert.equal(s39shares.length, 2);

  const seed = await S39.bip39.mnemonicToSeed(await S39.bip39.entropyToMnemonic(entropy), '');
  const sections = await S39.wallet.deriveWalletInfo(seed);
  assert.equal(sections.length, 6);

  const collector = new S39.entropy.EntropyCollector(16);
  collector.lastSample = -1000;
  collector.addPointerSample(10, 20, 0);
  assert.equal(collector.collectedBits, 1);
  collector.destroy();
});
