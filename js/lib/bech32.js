'use strict';
// Bech32 encoding (BIP-0173) for SegWit v0 addresses.
// Implemented from the BIP-0173 reference implementation
// (https://github.com/sipa/bech32/blob/master/ref/javascript/bech32.js, MIT).
// Encode-only: this app never parses addresses.
(function (S39) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((b >>> i) & 1) chk ^= GEN[i];
      }
    }
    return chk;
  }

  function hrpExpand(hrp) {
    const out = [];
    for (const c of hrp) out.push(c.charCodeAt(0) >>> 5);
    out.push(0);
    for (const c of hrp) out.push(c.charCodeAt(0) & 31);
    return out;
  }

  function createChecksum(hrp, data) {
    const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
    const poly = polymod(values) ^ 1; // bech32 constant (not bech32m)
    const out = [];
    for (let i = 0; i < 6; i++) out.push((poly >>> (5 * (5 - i))) & 31);
    return out;
  }

  function convertBits(data, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const out = [];
    const maxv = (1 << toBits) - 1;
    for (const value of data) {
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        out.push((acc >>> bits) & maxv);
      }
    }
    if (pad && bits > 0) out.push((acc << (toBits - bits)) & maxv);
    return out;
  }

  /** Encode a SegWit v0 P2WPKH/P2WSH address (hrp 'bc' for mainnet). */
  function encodeSegwitV0(hrp, program) {
    const data = [0, ...convertBits(program, 8, 5, true)];
    const combined = [...data, ...createChecksum(hrp, data)];
    let out = hrp + '1';
    for (const v of combined) out += CHARSET[v];
    return out;
  }

  S39.bech32 = { encodeSegwitV0 };
})(globalThis.S39 = globalThis.S39 || {});
