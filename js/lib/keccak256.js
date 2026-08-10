'use strict';
// Keccak-256 (the pre-NIST padding variant used by Ethereum).
// Implemented from the Keccak reference specification
// (https://keccak.team/keccak_specs_summary.html). Round constants and
// rotation offsets are *computed* from the spec's LFSR / permutation
// definitions rather than transcribed, to rule out table typos.
// Verified against known-answer tests in test/keccak256.test.mjs.
(function (S39) {
  const ROUNDS = 24;
  const RATE_BYTES = 136; // 1088-bit rate for Keccak-256

  // Round constants RC[i] via LFSR x^8 + x^6 + x^5 + x^4 + 1 (spec section 1.2)
  const RC = (() => {
    const rc = [];
    let lfsr = 0x01;
    for (let round = 0; round < ROUNDS; round++) {
      let c = 0n;
      for (let j = 0; j < 7; j++) {
        const bitPos = (1 << j) - 1; // 0, 1, 3, 7, 15, 31, 63
        if (lfsr & 1) c |= 1n << BigInt(bitPos);
        lfsr = lfsr & 0x80 ? ((lfsr << 1) ^ 0x71) & 0xff : (lfsr << 1) & 0xff;
      }
      rc.push(c);
    }
    return rc;
  })();

  // Rotation offsets r[x][y]: walk (x,y) -> (y, 2x+3y) starting at (1,0)
  const ROT = (() => {
    const rot = Array.from({ length: 5 }, () => new Array(5).fill(0));
    let x = 1;
    let y = 0;
    for (let t = 0; t < 24; t++) {
      rot[x][y] = (((t + 1) * (t + 2)) / 2) % 64;
      const nx = y;
      const ny = (2 * x + 3 * y) % 5;
      x = nx;
      y = ny;
    }
    return rot;
  })();

  const MASK = (1n << 64n) - 1n;

  function rotl64(v, n) {
    if (n === 0) return v;
    return ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK;
  }

  function keccakF(state) {
    for (let round = 0; round < ROUNDS; round++) {
      // theta
      const c = new Array(5);
      for (let x = 0; x < 5; x++) {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
      }
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d;
      }
      // rho + pi
      const b = new Array(25);
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], ROT[x][y]);
        }
      }
      // chi
      for (let x = 0; x < 5; x++) {
        for (let y = 0; y < 5; y++) {
          state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK & b[((x + 2) % 5) + 5 * y]);
        }
      }
      // iota
      state[0] ^= RC[round];
    }
  }

  function keccak256(data) {
    const state = new Array(25).fill(0n);
    // absorb
    let offset = 0;
    const block = new Uint8Array(RATE_BYTES);
    while (data.length - offset >= RATE_BYTES) {
      for (let i = 0; i < RATE_BYTES; i++) block[i] = data[offset + i];
      absorbBlock(state, block);
      offset += RATE_BYTES;
    }
    // final block with Keccak padding 0x01 ... 0x80
    block.fill(0);
    for (let i = 0; i < data.length - offset; i++) block[i] = data[offset + i];
    block[data.length - offset] ^= 0x01;
    block[RATE_BYTES - 1] ^= 0x80;
    absorbBlock(state, block);
    // squeeze 32 bytes (single block, rate > 32)
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
      let lane = state[i];
      for (let j = 0; j < 8; j++) {
        out[i * 8 + j] = Number(lane & 0xffn);
        lane >>= 8n;
      }
    }
    state.fill(0n);
    return out;
  }

  function absorbBlock(state, block) {
    for (let i = 0; i < RATE_BYTES / 8; i++) {
      let lane = 0n;
      for (let j = 7; j >= 0; j--) {
        lane = (lane << 8n) | BigInt(block[i * 8 + j]);
      }
      state[i] ^= lane;
    }
    keccakF(state);
  }

  S39.keccak256 = keccak256;
})(globalThis.S39 = globalThis.S39 || {});
