import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39, readVectors } from './load.mjs';

const S39 = loadS39();
const { bytesToHex, hexToBytes, utf8ToBytes } = S39.util;

test('keccak256 known answers', () => {
  assert.equal(
    bytesToHex(S39.keccak256(new Uint8Array(0))),
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
  );
  assert.equal(
    bytesToHex(S39.keccak256(utf8ToBytes('abc'))),
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
  );
  assert.equal(
    bytesToHex(S39.keccak256(utf8ToBytes('The quick brown fox jumps over the lazy dog'))),
    '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'
  );
});

test('ripemd160 official test vectors', () => {
  const vectors = [
    ['', '9c1185a5c5e9fc54612808977ee8f548b2258d31'],
    ['a', '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe'],
    ['abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc'],
    ['message digest', '5d0689ef49d2fae572b881b123a85ffa21595f36'],
    ['abcdefghijklmnopqrstuvwxyz', 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc'],
    ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '12a053384a9c0c88e405a06c27dcf49ada62eb2b'],
    ['12345678901234567890123456789012345678901234567890123456789012345678901234567890', '9b752e45573d4b39f4dbd3323cab82bf63326bfb'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(bytesToHex(S39.ripemd160(utf8ToBytes(input))), expected, `ripemd160(${JSON.stringify(input)})`);
  }
});

test('keccak256/ripemd160 multi-block cross-reference (noble-hashes 2.3.0)', () => {
  const ref = readVectors('generated-reference.json');
  for (const { len, hash } of ref.keccak256) {
    const data = new Uint8Array(len).map((_, i) => i & 0xff);
    assert.equal(bytesToHex(S39.keccak256(data)), hash, `keccak256 len=${len}`);
  }
  for (const { len, hash } of ref.ripemd160) {
    const data = new Uint8Array(len).map((_, i) => i & 0xff);
    assert.equal(bytesToHex(S39.ripemd160(data)), hash, `ripemd160 len=${len}`);
  }
});

test('webcrypto wrappers against RFC test values', async () => {
  // FIPS 180-4 / RFC 6234: sha256('abc')
  assert.equal(
    bytesToHex(await S39.hash.sha256(utf8ToBytes('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  // RFC 4231 test case 2: HMAC-SHA256/512 with key 'Jefe'
  assert.equal(
    bytesToHex(await S39.hash.hmacSha256(utf8ToBytes('Jefe'), utf8ToBytes('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
  );
  // RFC 6070 PBKDF2-HMAC-SHA1 is not exposed; use PBKDF2-HMAC-SHA256 vector
  // from RFC 7914 section 11: PBKDF2-SHA256(P='passwd', S='salt', c=1, dkLen=64)
  assert.equal(
    bytesToHex(await S39.hash.pbkdf2Sha256(utf8ToBytes('passwd'), utf8ToBytes('salt'), 1, 64)),
    '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc' +
      '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'
  );
});

test('secp256k1 public key derivation', () => {
  const one = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  assert.equal(
    bytesToHex(S39.secp256k1.getPublicKey(one, true)),
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
  );
  const two = hexToBytes('0000000000000000000000000000000000000000000000000000000000000002');
  assert.equal(
    bytesToHex(S39.secp256k1.getPublicKey(two, true)),
    '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
  );
  // deadbeef-ish scalar, cross-checked with noble-secp256k1
  const ref = readVectors('generated-reference.json');
  for (const [path, entry] of Object.entries(ref.reference_keys)) {
    assert.equal(
      bytesToHex(S39.secp256k1.getPublicKey(hexToBytes(entry.privateKey), true)),
      entry.publicKeyCompressed,
      `pubkey for ${path}`
    );
  }
});
