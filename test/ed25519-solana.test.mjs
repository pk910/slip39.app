import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39, readVectors } from './load.mjs';

const S39 = loadS39();
const { bytesToHex, hexToBytes } = S39.util;

const MNEMONIC = ('abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon about').split(' ');

test('ed25519 public keys (RFC 8032 / noble cross-reference)', async () => {
  const ref = readVectors('generated-reference.json');
  assert.ok(ref.ed25519_pubkeys.length >= 5);
  for (const { secret, public: expected } of ref.ed25519_pubkeys) {
    const pub = await S39.ed25519.getPublicKey(hexToBytes(secret));
    assert.equal(bytesToHex(pub), expected, `pubkey for secret ${secret.slice(0, 16)}…`);
  }
});

test('SLIP-0010 ed25519 official test vectors (both seeds, all chains)', async () => {
  const vectors = readVectors('slip10-ed25519.json');
  assert.equal(vectors.length, 2);
  for (const vector of vectors) {
    const seed = hexToBytes(vector.seed);
    for (const chain of vector.chains) {
      const node = await S39.slip10.derivePath(seed, chain.path);
      assert.equal(bytesToHex(node.key), chain.private, `private key at ${chain.path}`);
      assert.equal(bytesToHex(node.chainCode), chain.chainCode, `chain code at ${chain.path}`);
      // SLIP-0010 serializes ed25519 public keys with a 0x00 prefix byte
      const pub = await S39.ed25519.getPublicKey(node.key);
      assert.equal('00' + bytesToHex(pub), chain.public, `public key at ${chain.path}`);
    }
  }
});

test('non-hardened segments are rejected for ed25519', async () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  await assert.rejects(S39.slip10.derivePath(seed, "m/44'/501'/0'/0"), /hardened/);
});

test('Solana addresses match ed25519-hd-key cross-reference', async () => {
  const ref = readVectors('generated-reference.json');
  const seed = await S39.bip39.mnemonicToSeed(MNEMONIC, '');

  // via the custom path resolver
  const custom = await S39.wallet.deriveCustomPath(seed, "m/44'/501'/0'", 'solana');
  assert.equal(custom.xpub, null);
  assert.equal(custom.rows[0].address, ref.solana["m/44'/501'/0'"]);
  assert.equal(custom.rows[1].path, "m/44'/501'/0'/0'");
  assert.equal(custom.rows[1].address, ref.solana["m/44'/501'/0'/0'"]);

  // via the standard Info sections
  const sections = await S39.wallet.deriveWalletInfo(seed);
  const sol = sections.find((s) => s.coin === 'SOL');
  assert.ok(sol);
  assert.equal(sol.xpub, null);
  assert.equal(sol.addresses[0].path, "m/44'/501'/0'/0'");
  assert.equal(sol.addresses[0].address, ref.solana["m/44'/501'/0'/0'"]);
  assert.equal(sol.addresses[1].address, ref.solana["m/44'/501'/1'/0'"]);
});

test('TRON address encoding (USDT contract vector) and derivation shape', async () => {
  // Well-known TRON base58check pair: hex 41a614f8… <-> TR7NHqje… (USDT TRC-20 contract)
  assert.equal(
    await S39.base58.encodeBase58Check(hexToBytes('41a614f803b6fd780986a42c78ec9c7f77e6ded13c')),
    'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
  );

  const seed = await S39.bip39.mnemonicToSeed(MNEMONIC, '');
  const sections = await S39.wallet.deriveWalletInfo(seed);
  const trx = sections.find((s) => s.coin === 'TRX');
  assert.ok(trx);
  assert.equal(trx.accountPath, "m/44'/195'/0'");
  for (const { address } of trx.addresses) {
    assert.match(address, /^T[1-9A-HJ-NP-Za-km-z]{33}$/, 'TRON mainnet address format');
  }

  // TRON reuses the Ethereum keccak pipeline: the same key at the same path
  // must yield a TRON address whose payload equals the ETH address bytes.
  const eth = await S39.wallet.deriveCustomPath(seed, "m/44'/195'/0'/0", 'eth');
  const tron = await S39.wallet.deriveCustomPath(seed, "m/44'/195'/0'/0", 'tron');
  const rebuilt = await S39.base58.encodeBase58Check(
    hexToBytes('41' + eth.rows[1].address.slice(2).toLowerCase())
  );
  assert.equal(tron.rows[1].address, rebuilt);
});
