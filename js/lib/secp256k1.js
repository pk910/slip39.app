'use strict';
// Minimal secp256k1: public-key derivation only (no signing, no ECDH).
// Curve parameters from SEC 2 v2 (https://www.secg.org/sec2-v2.pdf), section 2.4.1.
// Point arithmetic uses Jacobian coordinates over native BigInt.
// This tool runs offline and derives keys locally, so remote timing
// side-channels do not apply; correctness is enforced by test vectors
// (BIP-32 / BIP-84 reference vectors exercise this code end-to-end).
(function (S39) {
  const P = 2n ** 256n - 2n ** 32n - 977n;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  function mod(a, m) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function modInv(a, m) {
    // extended Euclidean algorithm
    let [old_r, r] = [mod(a, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error('modular inverse does not exist');
    return mod(old_s, m);
  }

  // Jacobian point: [X, Y, Z] with x = X/Z^2, y = Y/Z^3. Infinity: Z = 0.
  const INF = [1n, 1n, 0n];

  function jDouble([x, y, z]) {
    if (z === 0n) return INF;
    const a = mod(x * x, P);
    const b = mod(y * y, P);
    const c = mod(b * b, P);
    const d = mod(2n * (mod((x + b) * (x + b), P) - a - c), P);
    const e = mod(3n * a, P);
    const f = mod(e * e, P);
    const x3 = mod(f - 2n * d, P);
    const y3 = mod(e * (d - x3) - 8n * c, P);
    const z3 = mod(2n * y * z, P);
    return [x3, y3, z3];
  }

  function jAdd(p1, p2) {
    const [x1, y1, z1] = p1;
    const [x2, y2, z2] = p2;
    if (z1 === 0n) return p2;
    if (z2 === 0n) return p1;
    const z1z1 = mod(z1 * z1, P);
    const z2z2 = mod(z2 * z2, P);
    const u1 = mod(x1 * z2z2, P);
    const u2 = mod(x2 * z1z1, P);
    const s1 = mod(y1 * z2 * z2z2, P);
    const s2 = mod(y2 * z1 * z1z1, P);
    if (u1 === u2) {
      if (s1 === s2) return jDouble(p1);
      return INF;
    }
    const h = mod(u2 - u1, P);
    const i = mod(4n * h * h, P);
    const j = mod(h * i, P);
    const r = mod(2n * (s2 - s1), P);
    const v = mod(u1 * i, P);
    const x3 = mod(r * r - j - 2n * v, P);
    const y3 = mod(r * (v - x3) - 2n * s1 * j, P);
    const z3 = mod(2n * h * z1 * z2, P);
    return [x3, y3, z3];
  }

  function jMultiplyG(k) {
    let result = INF;
    let addend = [GX, GY, 1n];
    while (k > 0n) {
      if (k & 1n) result = jAdd(result, addend);
      addend = jDouble(addend);
      k >>= 1n;
    }
    return result;
  }

  function toAffine([x, y, z]) {
    if (z === 0n) throw new Error('point at infinity');
    const zInv = modInv(z, P);
    const zInv2 = mod(zInv * zInv, P);
    return [mod(x * zInv2, P), mod(y * zInv2 * zInv, P)];
  }

  function bytesToBigInt(bytes) {
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return v;
  }

  function bigIntTo32Bytes(v) {
    const out = new Uint8Array(32);
    for (let i = 31; i >= 0; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }

  /** True if the 32-byte scalar is a valid private key (0 < k < n). */
  function isValidPrivateKey(privateKey) {
    const k = bytesToBigInt(privateKey);
    return k > 0n && k < N;
  }

  /** Derive the public key for a 32-byte private key. */
  function getPublicKey(privateKey, compressed) {
    if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
      throw new Error('private key must be 32 bytes');
    }
    const k = bytesToBigInt(privateKey);
    if (k <= 0n || k >= N) throw new Error('private key out of range');
    const [x, y] = toAffine(jMultiplyG(k));
    const xb = bigIntTo32Bytes(x);
    if (compressed) {
      const out = new Uint8Array(33);
      out[0] = y & 1n ? 0x03 : 0x02;
      out.set(xb, 1);
      return out;
    }
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(xb, 1);
    out.set(bigIntTo32Bytes(y), 33);
    return out;
  }

  /** (a + b) mod n over 32-byte scalars — used for BIP-32 child key derivation. */
  function scalarAddModN(a, b) {
    const sum = mod(bytesToBigInt(a) + bytesToBigInt(b), N);
    return bigIntTo32Bytes(sum);
  }

  /** True if the 32-byte value is a valid field element to use as IL in BIP-32 (IL < n). */
  function isLessThanN(bytes32) {
    return bytesToBigInt(bytes32) < N;
  }

  S39.secp256k1 = { getPublicKey, isValidPrivateKey, scalarAddModN, isLessThanN };
})(globalThis.S39 = globalThis.S39 || {});
