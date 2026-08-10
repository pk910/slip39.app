'use strict';
// GF(256) arithmetic with the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11B),
// as required by SLIP-0039, plus Lagrange interpolation over byte vectors.
(function (S39) {
  const EXP = new Uint8Array(255);
  const LOG = new Uint8Array(256);
  {
    let poly = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = poly;
      LOG[poly] = i;
      // multiply poly by the generator 3 (0x03), a primitive element of the field
      poly ^= ((poly << 1) ^ (poly & 0x80 ? 0x1b : 0)) & 0xff;
    }
  }

  /**
   * Lagrange interpolation: evaluates the polynomial defined by the given
   * points {x, data} at position x, independently for every byte.
   */
  function interpolate(shares, x) {
    const xCoords = new Set(shares.map((s) => s.x));
    if (xCoords.size !== shares.length) throw new Error('duplicate share index');
    if (xCoords.has(x)) {
      return Uint8Array.from(shares.find((s) => s.x === x).data);
    }
    const len = shares[0].data.length;
    if (shares.some((s) => s.data.length !== len)) {
      throw new Error('shares have mismatching lengths');
    }

    let logProd = 0;
    for (const s of shares) logProd += LOG[s.x ^ x];

    const result = new Uint8Array(len);
    for (const s of shares) {
      let logBasisDenom = LOG[s.x ^ x];
      for (const other of shares) {
        if (other.x !== s.x) logBasisDenom += LOG[s.x ^ other.x];
      }
      const logBasis = (logProd - logBasisDenom + 255 * 255) % 255;
      for (let k = 0; k < len; k++) {
        const v = s.data[k];
        if (v !== 0) result[k] ^= EXP[(LOG[v] + logBasis) % 255];
      }
    }
    return result;
  }

  S39.slip39gf = { interpolate };
})(globalThis.S39 = globalThis.S39 || {});
