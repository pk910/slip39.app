'use strict';
// RIPEMD-160.
// Ported (ESM -> classic script, streaming API removed) from @noble/hashes
// v2.3.0 legacy.js — https://github.com/paulmillr/noble-hashes (MIT).
// Index and shift tables are derived from the Rho/Pi permutations exactly as
// in the original. Verified against the official test vectors from
// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html in the test suite.
(function (S39) {
  const Rho = [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8];
  const Id = Array.from({ length: 16 }, (_, i) => i);
  const Pi = Id.map((i) => (9 * i + 5) % 16);

  // Five message-word orderings per lane: apply Rho permutation repeatedly
  const idxL = [Id];
  const idxR = [Pi];
  for (let i = 0; i < 4; i++) {
    idxL.push(idxL[i].map((k) => Rho[k]));
    idxR.push(idxR[i].map((k) => Rho[k]));
  }

  const shifts = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7],
    [13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9],
    [14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6],
    [15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5],
  ];
  const shiftsL = idxL.map((idx, i) => idx.map((j) => shifts[i][j]));
  const shiftsR = idxR.map((idx, i) => idx.map((j) => shifts[i][j]));

  const Kl = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const Kr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  function rotl(word, shift) {
    return (word << shift) | (word >>> (32 - shift));
  }

  function f(group, x, y, z) {
    if (group === 0) return x ^ y ^ z;
    if (group === 1) return (x & y) | (~x & z);
    if (group === 2) return (x | ~y) ^ z;
    if (group === 3) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function ripemd160(data) {
    // MD-style padding: 0x80, zeros, 64-bit little-endian bit length
    const bitLen = data.length * 8;
    const padded = new Uint8Array((Math.floor((data.length + 8) / 64) + 1) * 64);
    padded.set(data);
    padded[data.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, bitLen >>> 0, true);
    dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);

    let h0 = 0x67452301 | 0;
    let h1 = 0xefcdab89 | 0;
    let h2 = 0x98badcfe | 0;
    let h3 = 0x10325476 | 0;
    let h4 = 0xc3d2e1f0 | 0;

    const buf = new Uint32Array(16);
    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i++) buf[i] = dv.getUint32(offset + i * 4, true);
      let al = h0, ar = h0, bl = h1, br = h1, cl = h2, cr = h2, dl = h3, dr = h3, el = h4, er = h4;
      for (let group = 0; group < 5; group++) {
        const rGroup = 4 - group;
        const hbl = Kl[group];
        const hbr = Kr[group];
        const rl = idxL[group];
        const rr = idxR[group];
        const sl = shiftsL[group];
        const sr = shiftsR[group];
        for (let i = 0; i < 16; i++) {
          const tl = (rotl((al + f(group, bl, cl, dl) + buf[rl[i]] + hbl) | 0, sl[i]) + el) | 0;
          al = el; el = dl; dl = rotl(cl, 10) | 0; cl = bl; bl = tl;
        }
        for (let i = 0; i < 16; i++) {
          const tr = (rotl((ar + f(rGroup, br, cr, dr) + buf[rr[i]] + hbr) | 0, sr[i]) + er) | 0;
          ar = er; er = dr; dr = rotl(cr, 10) | 0; cr = br; br = tr;
        }
      }
      const t0 = (h1 + cl + dr) | 0;
      const t1 = (h2 + dl + er) | 0;
      const t2 = (h3 + el + ar) | 0;
      const t3 = (h4 + al + br) | 0;
      const t4 = (h0 + bl + cr) | 0;
      h0 = t0; h1 = t1; h2 = t2; h3 = t3; h4 = t4;
    }
    buf.fill(0);
    padded.fill(0);

    const out = new Uint8Array(20);
    const outDv = new DataView(out.buffer);
    outDv.setUint32(0, h0, true);
    outDv.setUint32(4, h1, true);
    outDv.setUint32(8, h2, true);
    outDv.setUint32(12, h3, true);
    outDv.setUint32(16, h4, true);
    return out;
  }

  S39.ripemd160 = ripemd160;
})(globalThis.S39 = globalThis.S39 || {});
