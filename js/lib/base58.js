'use strict';
// Base58 and Base58Check encoding (Bitcoin alphabet).
// Implemented from the Base58Check specification
// (https://en.bitcoin.it/wiki/Base58Check_encoding). Encode-only.
(function (S39) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  function encodeBase58(bytes) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    let out = '';
    while (v > 0n) {
      out = ALPHABET[Number(v % 58n)] + out;
      v /= 58n;
    }
    for (const b of bytes) {
      if (b !== 0) break;
      out = '1' + out;
    }
    return out;
  }

  /** Base58Check: payload || first 4 bytes of sha256(sha256(payload)). */
  async function encodeBase58Check(payload) {
    const h1 = await S39.hash.sha256(payload);
    const h2 = await S39.hash.sha256(h1);
    const full = S39.util.concatBytes(payload, h2.subarray(0, 4));
    return encodeBase58(full);
  }

  S39.base58 = { encodeBase58, encodeBase58Check };
})(globalThis.S39 = globalThis.S39 || {});
