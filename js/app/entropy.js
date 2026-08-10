'use strict';
// Hardened randomness: the OS CSPRNG (crypto.getRandomValues) XOR-mixed with
// user-supplied pointer/keyboard entropy. The output is never weaker than the
// stronger of the two sources: a backdoored CSPRNG is masked by user entropy,
// weak user entropy is masked by the CSPRNG.
(function (S39) {
  const { concatBytes, wipeBytes } = S39.util;

  // Fixed-size ring buffer for incoming samples: it starts zero-filled, each
  // sample overwrites bytes at an advancing position (wrapping around), and
  // every completed pass is absorbed into the pool WITHOUT clearing the
  // buffer — so an observer (and the UI's live viewer) sees a stable buffer
  // with changes rippling left-to-right, bitaddress.org-style.
  const BUFFER_BYTES = 264;

  class EntropyCollector {
    constructor(targetBits) {
      this.targetBits = targetBits;
      this.collectedBits = 0;
      this.totalSamples = 0;
      this.flushCount = 0;
      this.pool = S39.native.randomBytes(32);
      this.buffer = new Uint8Array(BUFFER_BYTES);
      this.writePos = 0;
      this.dirty = false;
      this.lastSample = 0;
      this.lastX = -1;
      this.lastY = -1;
      this.queue = Promise.resolve();
      this.onProgress = null;
    }

    _write(byte) {
      this.buffer[this.writePos] = byte;
      this.writePos += 1;
      if (this.writePos >= this.buffer.length) {
        this.writePos = 0;
        this._flush();
      }
    }

    /**
     * Feed a pointer sample. Credits at most 1 bit per sample, max one sample
     * per 10 ms. Returns true when the sample was accepted.
     */
    addPointerSample(x, y, extra) {
      const now = performance.now();
      if (now - this.lastSample < 10) return false;
      if (x === this.lastX && y === this.lastY) return false;
      this.lastSample = now;
      this.lastX = x;
      this.lastY = y;
      // 3 dense bytes per sample: position, position product (as
      // bitaddress.org seeds clientX*clientY), µs timestamp, position high
      // bits and pointer pressure, XOR-folded pairwise so no slot is
      // constant-prone and the buffer sweep stays slow enough to follow.
      const t = Math.floor(now * 1000);
      const product = Math.abs(x * y);
      for (const byte of [
        (x ^ product ^ (product >> 8) ^ (product >> 16)) & 0xff,
        (y ^ t) & 0xff,
        (((x >> 8) << 4) ^ (y >> 8) ^ (extra || 0) ^ (t >> 8)) & 0xff,
      ]) {
        this._write(byte);
      }
      this.dirty = true;
      this.totalSamples += 1;
      if (this.collectedBits < this.targetBits) {
        this.collectedBits += 1;
        if (this.onProgress) this.onProgress(this.collectedBits, this.targetBits);
      }
      return true;
    }

    addKeySample(code) {
      return this.addPointerSample(code & 0xffff, Math.floor(performance.now()) & 0xffff, code);
    }

    /** Absorb the current buffer into the pool. The buffer is NOT cleared. */
    _flush() {
      if (!this.dirty) return;
      this.dirty = false;
      const data = Uint8Array.from(this.buffer);
      this.flushCount += 1;
      this.queue = this.queue.then(async () => {
        const next = await S39.hash.sha256(concatBytes(this.pool, data));
        wipeBytes(this.pool);
        wipeBytes(data);
        this.pool = next;
      });
    }

    get complete() {
      return this.collectedBits >= this.targetBits;
    }

    /** Absorb any pending samples and return a copy of the pool state. */
    async snapshot() {
      this._flush();
      await this.queue;
      return Uint8Array.from(this.pool);
    }

    destroy() {
      wipeBytes(this.buffer);
      wipeBytes(this.pool);
      this.writePos = 0;
      this.collectedBits = 0;
      this.dirty = false;
    }
  }

  /**
   * Derive `n` hardened random bytes from the user-entropy pool + CSPRNG:
   * out = CSPRNG(n) XOR SHA256-expand(pool, counter, fresh CSPRNG salt).
   */
  async function hardenedRandomBytes(n, pool) {
    const base = S39.native.randomBytes(n);
    if (!pool) return base; // no user entropy collected: pure CSPRNG
    const out = new Uint8Array(n);
    const salt = S39.native.randomBytes(16);
    for (let block = 0; block * 32 < n; block++) {
      const counter = new Uint8Array([block >>> 24, (block >>> 16) & 0xff, (block >>> 8) & 0xff, block & 0xff]);
      const expanded = await S39.hash.sha256(concatBytes(pool, counter, salt));
      for (let i = 0; i < 32 && block * 32 + i < n; i++) {
        out[block * 32 + i] = base[block * 32 + i] ^ expanded[i];
      }
      wipeBytes(expanded);
    }
    wipeBytes(base);
    wipeBytes(salt);
    return out;
  }

  /**
   * Pre-computes a hardened random stream so synchronous consumers
   * (the Shamir splitter) can draw from it. Throws when exhausted.
   */
  async function createHardenedRng(pool, bytes = 4096) {
    const stream = await hardenedRandomBytes(bytes, pool);
    let offset = 0;
    const next = (n) => {
      if (offset + n > stream.length) throw new Error('hardened RNG stream exhausted');
      const out = stream.slice(offset, offset + n);
      offset += n;
      return out;
    };
    next.destroy = () => wipeBytes(stream);
    return next;
  }

  S39.entropy = { EntropyCollector, hardenedRandomBytes, createHardenedRng };
})(globalThis.S39 = globalThis.S39 || {});
