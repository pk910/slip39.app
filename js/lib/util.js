'use strict';
// Byte/hex/bit helpers. Original code for slip39.app, no external origin.
(function (S39) {
  const HEX = '0123456789abcdef';

  // Capture the native RNG at load time (this file loads first). All code in
  // this app draws randomness through S39.native, so replacing the global
  // crypto object later has no effect. The security checks additionally
  // compare these captured references against the live globals to detect
  // such tampering.
  const cryptoObj = globalThis.crypto;
  const rawGetRandomValues = cryptoObj && cryptoObj.getRandomValues;
  S39.native = Object.freeze({
    getRandomValues: rawGetRandomValues ? rawGetRandomValues.bind(cryptoObj) : null,
    rawGetRandomValues,
    randomBytes: (n) => {
      if (!rawGetRandomValues) throw new Error('crypto.getRandomValues is unavailable');
      return rawGetRandomValues.call(cryptoObj, new Uint8Array(n));
    },
  });

  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += HEX[bytes[i] >>> 4] + HEX[bytes[i] & 15];
    }
    return out;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('invalid hex string');
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function concatBytes(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
      out.set(a, off);
      off += a.length;
    }
    return out;
  }

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  /** Best-effort in-place wipe of a Uint8Array (overwrite with random, then zeros). */
  function wipeBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) return;
    try {
      S39.native.getRandomValues(bytes.length <= 65536 ? bytes : bytes.subarray(0, 65536));
    } catch (e) {
      /* getRandomValues caps at 64KiB; zero-fill below still applies */
    }
    bytes.fill(0xff);
    bytes.fill(0x00);
  }

  S39.util = { bytesToHex, hexToBytes, concatBytes, utf8ToBytes, bytesEqual, wipeBytes };
})(globalThis.S39 = globalThis.S39 || {});
