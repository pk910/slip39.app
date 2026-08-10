'use strict';
// SLIP-0010 hierarchical key derivation for ed25519 (hardened-only), as used
// by Solana wallets (Phantom, Solflare) with paths like m/44'/501'/0'/0'.
// Implemented from https://github.com/satoshilabs/slips/blob/master/slip-0010.md
// and verified against its official ed25519 test vectors in the test suite.
(function (S39) {
  const { concatBytes, utf8ToBytes, wipeBytes } = S39.util;
  const HARDENED = 0x80000000;

  async function masterKey(seed) {
    const i = await S39.hash.hmacSha512(utf8ToBytes('ed25519 seed'), seed);
    const node = { key: i.slice(0, 32), chainCode: i.slice(32) };
    wipeBytes(i);
    return node;
  }

  /** Derive a hardened child. `index` is the raw index (without the hardened offset). */
  async function deriveChild(node, index) {
    const data = new Uint8Array(37);
    data.set(node.key, 1);
    new DataView(data.buffer).setUint32(33, (index + HARDENED) >>> 0, false);
    const i = await S39.hash.hmacSha512(node.chainCode, data);
    wipeBytes(data);
    const child = { key: i.slice(0, 32), chainCode: i.slice(32) };
    wipeBytes(i);
    return child;
  }

  /**
   * Derive a path like "m/44'/501'/0'/0'". Every segment MUST be hardened
   * (ed25519 has no non-hardened derivation) — plain segments are rejected.
   */
  async function derivePath(seed, path) {
    const parts = path.split('/');
    if (parts[0] !== 'm') throw new Error('path must start with "m"');
    let node = await masterKey(seed);
    for (const part of parts.slice(1)) {
      if (!part.endsWith("'") && !part.endsWith('h')) {
        throw new Error(
          `ed25519 (Solana) only supports hardened derivation — write "${part}'" instead of "${part}"`
        );
      }
      const index = parseInt(part.slice(0, -1), 10);
      if (!Number.isInteger(index) || index < 0 || index >= HARDENED) {
        throw new Error(`invalid path segment "${part}"`);
      }
      const child = await deriveChild(node, index);
      wipeNode(node);
      node = child;
    }
    return node;
  }

  function wipeNode(node) {
    wipeBytes(node.key);
    wipeBytes(node.chainCode);
  }

  S39.slip10 = { masterKey, deriveChild, derivePath, wipeNode };
})(globalThis.S39 = globalThis.S39 || {});
