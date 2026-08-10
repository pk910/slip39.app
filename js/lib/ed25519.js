'use strict';
// Ed25519 public-key derivation (no signing), implemented from RFC 8032
// (https://www.rfc-editor.org/rfc/rfc8032). Used for Solana addresses via
// SLIP-0010. Point arithmetic uses the unified twisted-Edwards addition
// formulas from RFC 8032 section 5.1.4 over native BigInt; the curve
// constant d is computed from the spec definition rather than transcribed.
// Verified against RFC 8032 / noble-ed25519 cross-reference vectors and the
// official SLIP-0010 test vectors in the test suite.
(function (S39) {
  const P = 2n ** 255n - 19n;

  function mod(a) {
    const r = a % P;
    return r >= 0n ? r : r + P;
  }

  function modInv(a) {
    let [old_r, r] = [mod(a), P];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s);
  }

  // d = -121665/121666 mod p
  const D = mod(-121665n * modInv(121666n));
  const D2 = mod(2n * D);

  // base point B (RFC 8032 section 5.1)
  const BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
  const BY = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;

  // extended homogeneous coordinates {x, y, z, t} with t = x*y/z
  const IDENTITY = { x: 0n, y: 1n, z: 1n, t: 0n };
  const BASE = { x: BX, y: BY, z: 1n, t: mod(BX * BY) };

  // unified addition (complete for edwards25519), RFC 8032 section 5.1.4
  function pointAdd(p1, p2) {
    const a = mod((p1.y - p1.x) * (p2.y - p2.x));
    const b = mod((p1.y + p1.x) * (p2.y + p2.x));
    const c = mod(p1.t * D2 * p2.t);
    const d = mod(2n * p1.z * p2.z);
    const e = b - a;
    const f = d - c;
    const g = d + c;
    const h = b + a;
    return { x: mod(e * f), y: mod(g * h), t: mod(e * h), z: mod(f * g) };
  }

  function scalarMultBase(scalar) {
    let result = IDENTITY;
    let addend = BASE;
    let s = scalar;
    while (s > 0n) {
      if (s & 1n) result = pointAdd(result, addend);
      addend = pointAdd(addend, addend);
      s >>= 1n;
    }
    return result;
  }

  function encodePoint(point) {
    const zInv = modInv(point.z);
    const x = mod(point.x * zInv);
    const y = mod(point.y * zInv);
    const out = new Uint8Array(32);
    let v = y;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    if (x & 1n) out[31] |= 0x80;
    return out;
  }

  /**
   * Derive the 32-byte ed25519 public key for a 32-byte private key seed
   * (RFC 8032 section 5.1.5: SHA-512, clamp, scalar-multiply the base point).
   */
  async function getPublicKey(privateSeed) {
    if (!(privateSeed instanceof Uint8Array) || privateSeed.length !== 32) {
      throw new Error('ed25519 private key must be 32 bytes');
    }
    const h = await S39.hash.sha512(privateSeed);
    const scalarBytes = h.slice(0, 32);
    scalarBytes[0] &= 248;
    scalarBytes[31] &= 127;
    scalarBytes[31] |= 64;
    let scalar = 0n;
    for (let i = 31; i >= 0; i--) {
      scalar = (scalar << 8n) | BigInt(scalarBytes[i]);
    }
    S39.util.wipeBytes(h);
    S39.util.wipeBytes(scalarBytes);
    const pub = encodePoint(scalarMultBase(scalar));
    scalar = 0n;
    return pub;
  }

  S39.ed25519 = { getPublicKey };
})(globalThis.S39 = globalThis.S39 || {});
