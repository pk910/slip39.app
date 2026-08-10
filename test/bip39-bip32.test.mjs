import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39, readVectors } from './load.mjs';

const S39 = loadS39();
const { bytesToHex, hexToBytes } = S39.util;

test('official BIP39 test vectors (trezor/python-mnemonic, passphrase TREZOR)', async () => {
  const vectors = readVectors('bip39-vectors.json').english;
  assert.ok(vectors.length >= 24);
  for (const [entropyHex, mnemonic, seedHex, xprv] of vectors) {
    const words = mnemonic.split(' ');
    // entropy -> mnemonic
    const generated = await S39.bip39.entropyToMnemonic(hexToBytes(entropyHex));
    assert.equal(generated.join(' '), mnemonic);
    // mnemonic -> entropy (checksum validation included)
    assert.equal(bytesToHex(await S39.bip39.mnemonicToEntropy(words)), entropyHex);
    // mnemonic -> seed
    const seed = await S39.bip39.mnemonicToSeed(words, 'TREZOR');
    assert.equal(bytesToHex(seed), seedHex);
    // seed -> BIP32 master xprv
    const node = await S39.bip32.fromMasterSeed(seed);
    assert.equal(await S39.bip32.toExtendedPrivateKey(node), xprv);
  }
});

test('invalid BIP39 checksum is rejected', async () => {
  const words = ('abandon abandon abandon abandon abandon abandon ' +
    'abandon abandon abandon abandon abandon abandon').split(' ');
  await assert.rejects(S39.bip39.mnemonicToEntropy(words), /checksum/);
  assert.equal(await S39.bip39.validateMnemonic(words), false);
});

test('BIP32 official test vector 1', async () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const root = await S39.bip32.fromMasterSeed(seed);
  assert.equal(
    await S39.bip32.toExtendedPrivateKey(root),
    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
  );
  const child = await S39.bip32.derivePath(root, "m/0'/1/2'/2/1000000000");
  assert.equal(
    await S39.bip32.toExtendedPrivateKey(child),
    'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
  );
});

test('BIP32 official test vector 2 (leading-zero handling)', async () => {
  const seed = hexToBytes(
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
  );
  const root = await S39.bip32.fromMasterSeed(seed);
  const child = await S39.bip32.derivePath(root, "m/0/2147483647'/1/2147483646'/2");
  assert.equal(
    await S39.bip32.toExtendedPrivateKey(child),
    'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
  );
});

test('BIP32 official test vector 3 (retention of leading zeros)', async () => {
  const seed = hexToBytes(
    '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'
  );
  const root = await S39.bip32.fromMasterSeed(seed);
  const child = await S39.bip32.derivePath(root, "m/0'");
  assert.equal(
    await S39.bip32.toExtendedPrivateKey(child),
    'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'
  );
});
