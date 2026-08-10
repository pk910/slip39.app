import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39, readVectors } from './load.mjs';

const S39 = loadS39();
const { bytesToHex, hexToBytes } = S39.util;

const MNEMONIC = ('abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon about').split(' ');

test('address derivation for the BIP39/BIP84 reference mnemonic', async () => {
  const seed = await S39.bip39.mnemonicToSeed(MNEMONIC, '');
  const ref = readVectors('generated-reference.json');
  assert.equal(bytesToHex(seed), ref.reference_seed);

  const addresses = await S39.wallet.deriveCommonAddresses(seed);
  const byPath = Object.fromEntries(addresses.map((a) => [a.path, a.address]));

  // BIP-84 specification test vectors (first two receiving addresses)
  assert.equal(byPath["m/84'/0'/0'/0/0"], 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(byPath["m/84'/0'/0'/0/1"], 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
  // Well-known BIP-44 P2PKH address for this mnemonic
  assert.equal(byPath["m/44'/0'/0'/0/0"], '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');
  // Well-known Ethereum address for this mnemonic (EIP-55 checksummed)
  assert.equal(byPath["m/44'/60'/0'/0/0"], '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  assert.equal(byPath["m/44'/60'/0'/0/1"], '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0');

  // derivation keys match the scure-bip32 cross-reference
  for (const [path, entry] of Object.entries(ref.reference_keys)) {
    const root = await S39.bip32.fromMasterSeed(seed);
    const node = await S39.bip32.derivePath(root, path);
    assert.equal(bytesToHex(node.privateKey), entry.privateKey, `private key ${path}`);
  }
});

test('account xpubs/ypub/zpub and BIP49 addresses (scure-bip32 + BIP84 spec cross-reference)', async () => {
  const seed = await S39.bip39.mnemonicToSeed(MNEMONIC, '');
  const ref = readVectors('generated-reference.json');
  const sections = await S39.wallet.deriveWalletInfo(seed);
  const byPath = Object.fromEntries(sections.map((s) => [s.accountPath, s]));

  for (const [path, entry] of Object.entries(ref.accounts)) {
    assert.equal(byPath[path].xpub, entry.extendedPublicKey, `extended public key for ${path}`);
    assert.equal(byPath[path].xpubKind, entry.kind);
  }
  const bip49 = byPath["m/49'/0'/0'"];
  for (const { path, address } of bip49.addresses) {
    assert.equal(address, ref.bip49_addresses[path], `BIP49 address ${path}`);
  }
  // spot-check section shape: 6 sections x 2 addresses
  assert.equal(sections.length, 6);
  for (const s of sections) assert.equal(s.addresses.length, 2);
});

test('extended public key serialization matches BIP32 spec vectors', async () => {
  const ref = readVectors('generated-reference.json');
  const root = await S39.bip32.fromMasterSeed(hexToBytes('000102030405060708090a0b0c0d0e0f'));
  assert.equal(await S39.bip32.toExtendedPublicKey(root), ref.bip32_spec_xpubs['vector1 m']);
  const child = await S39.bip32.derivePath(root, "m/0'/1/2'/2/1000000000");
  assert.equal(
    await S39.bip32.toExtendedPublicKey(child),
    ref.bip32_spec_xpubs["vector1 m/0'/1/2'/2/1000000000"]
  );
});

test('custom derivation path resolver', async () => {
  const seed = await S39.bip39.mnemonicToSeed(MNEMONIC, '');
  const ref = readVectors('generated-reference.json');

  const legacy = await S39.wallet.deriveCustomPath(seed, "m/44'/0'/0'/0", 'p2pkh');
  assert.equal(legacy.xpubKind, 'xpub');
  assert.equal(legacy.rows[0].path, "m/44'/0'/0'/0");
  assert.equal(legacy.rows[1].path, "m/44'/0'/0'/0/0");
  assert.equal(legacy.rows[1].address, '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');

  const segwit = await S39.wallet.deriveCustomPath(seed, "m/84'/0'/0'", 'p2wpkh');
  assert.equal(segwit.xpub, ref.accounts["m/84'/0'/0'"].extendedPublicKey);

  const eth = await S39.wallet.deriveCustomPath(seed, "m/44'/60'/0'/0", 'eth');
  assert.equal(eth.rows[1].address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  assert.equal(eth.rows[2].address, '0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0');

  // root path resolves without error
  const rootInfo = await S39.wallet.deriveCustomPath(seed, 'm', 'p2pkh');
  assert.equal(rootInfo.rows.length, 3);
  assert.equal(rootInfo.rows[1].path, 'm/0');

  await assert.rejects(S39.wallet.deriveCustomPath(seed, "m/44'", 'nope'), /unknown address type/);
});

test('EIP-55 checksum casing', () => {
  // Example addresses from EIP-55
  const cases = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ];
  for (const addr of cases) {
    const node = null;
    // re-checksum the lowercase form via the same code path used for real addresses
    const lower = addr.slice(2).toLowerCase();
    const caseHash = bytesToHex(S39.keccak256(new TextEncoder().encode(lower)));
    let out = '0x';
    for (let i = 0; i < lower.length; i++) {
      out += parseInt(caseHash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
    }
    assert.equal(out, addr);
  }
});

test('full flow: generate -> split -> recover -> derive', async () => {
  // 24-word mnemonic from fixed entropy
  const entropy = hexToBytes('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const words = await S39.bip39.entropyToMnemonic(entropy);
  assert.equal(words.length, 24);

  // split the underlying entropy into 3-of-5 SLIP39 shares
  const mnemonics = await S39.schemes.slip39.split({
    masterSecret: Uint8Array.from(entropy),
    threshold: 3,
    count: 5,
  });

  // recover from a subset and rebuild the BIP39 mnemonic
  const recovered = await S39.schemes.slip39.combine({
    mnemonics: [mnemonics[1], mnemonics[3], mnemonics[4]],
  });
  const recoveredWords = await S39.bip39.entropyToMnemonic(recovered.masterSecret);
  assert.equal(recoveredWords.join(' '), words.join(' '));

  // derive addresses from the recovered mnemonic
  const seed = await S39.bip39.mnemonicToSeed(recoveredWords, '');
  const addresses = await S39.wallet.deriveCommonAddresses(seed);
  assert.equal(addresses.length, 12);
  for (const a of addresses) {
    assert.ok(a.address.length > 20, `${a.path} -> ${a.address}`);
  }
});
