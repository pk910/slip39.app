'use strict';
// BIP-0032 hierarchical deterministic key derivation (private keys only).
// Implemented from the specification:
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
// Verified against the BIP-32 reference test vectors in the test suite.
(function (S39) {
  const { concatBytes, utf8ToBytes, wipeBytes } = S39.util;
  const HARDENED = 0x80000000;

  async function fromMasterSeed(seed) {
    const i = await S39.hash.hmacSha512(utf8ToBytes('Bitcoin seed'), seed);
    const node = {
      privateKey: i.slice(0, 32),
      chainCode: i.slice(32),
      depth: 0,
      parentFingerprint: 0,
      childIndex: 0,
    };
    wipeBytes(i);
    if (!S39.secp256k1.isValidPrivateKey(node.privateKey)) {
      throw new Error('invalid master key derived from seed (retry with different seed)');
    }
    return node;
  }

  async function fingerprint(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, true);
    const h = S39.ripemd160(await S39.hash.sha256(pub));
    const fp = ((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0;
    wipeBytes(h);
    return fp;
  }

  async function deriveChild(node, index) {
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, false);
    let data;
    if (index >= HARDENED) {
      data = concatBytes(new Uint8Array([0]), node.privateKey, indexBytes);
    } else {
      data = concatBytes(S39.secp256k1.getPublicKey(node.privateKey, true), indexBytes);
    }
    const i = await S39.hash.hmacSha512(node.chainCode, data);
    wipeBytes(data);
    const il = i.slice(0, 32);
    const chainCode = i.slice(32);
    wipeBytes(i);
    if (!S39.secp256k1.isLessThanN(il)) {
      // probability < 2^-127; BIP-32 mandates skipping to the next index
      wipeBytes(il);
      return deriveChild(node, index + 1);
    }
    const childKey = S39.secp256k1.scalarAddModN(il, node.privateKey);
    wipeBytes(il);
    if (!S39.secp256k1.isValidPrivateKey(childKey)) {
      wipeBytes(childKey);
      return deriveChild(node, index + 1);
    }
    return {
      privateKey: childKey,
      chainCode,
      depth: node.depth + 1,
      parentFingerprint: await fingerprint(node),
      childIndex: index,
    };
  }

  /** Derive a path like "m/44'/0'/0'/0/0". */
  async function derivePath(node, path) {
    const parts = path.split('/');
    if (parts[0] !== 'm') throw new Error('path must start with "m"');
    let current = node;
    for (const part of parts.slice(1)) {
      const hardened = part.endsWith("'") || part.endsWith('h');
      const index = parseInt(hardened ? part.slice(0, -1) : part, 10);
      if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
        throw new Error(`invalid path segment "${part}"`);
      }
      const next = await deriveChild(current, hardened ? index + HARDENED : index);
      if (current !== node) wipeNode(current);
      current = next;
    }
    return current;
  }

  // SLIP-0132 version bytes for extended public keys
  const XPUB_VERSIONS = {
    xpub: 0x0488b21e, // BIP44 P2PKH
    ypub: 0x049d7cb2, // BIP49 P2SH-P2WPKH
    zpub: 0x04b24746, // BIP84 P2WPKH
  };

  /** Serialize the node's *public* key as xpub/ypub/zpub (mainnet). */
  async function toExtendedPublicKey(node, versionName = 'xpub') {
    const version = XPUB_VERSIONS[versionName];
    if (!version) throw new Error(`unknown extended key version "${versionName}"`);
    const payload = new Uint8Array(78);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, version, false);
    payload[4] = node.depth;
    dv.setUint32(5, node.parentFingerprint, false);
    dv.setUint32(9, node.childIndex, false);
    payload.set(node.chainCode, 13);
    payload.set(S39.secp256k1.getPublicKey(node.privateKey, true), 45);
    return S39.base58.encodeBase58Check(payload);
  }

  /** Serialize as xprv (mainnet) — used for test-vector verification. */
  async function toExtendedPrivateKey(node) {
    const payload = new Uint8Array(78);
    const dv = new DataView(payload.buffer);
    dv.setUint32(0, 0x0488ade4, false); // xprv version
    payload[4] = node.depth;
    dv.setUint32(5, node.parentFingerprint, false);
    dv.setUint32(9, node.childIndex, false);
    payload.set(node.chainCode, 13);
    payload[45] = 0;
    payload.set(node.privateKey, 46);
    const encoded = await S39.base58.encodeBase58Check(payload);
    wipeBytes(payload);
    return encoded;
  }

  function wipeNode(node) {
    wipeBytes(node.privateKey);
    wipeBytes(node.chainCode);
  }

  S39.bip32 = {
    fromMasterSeed, derivePath, deriveChild,
    toExtendedPrivateKey, toExtendedPublicKey, wipeNode, HARDENED,
  };
})(globalThis.S39 = globalThis.S39 || {});
