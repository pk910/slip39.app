'use strict';
// Shamir39 ("shamir39-p1") — the legacy BIP39-share scheme used by
// iancoleman.github.io/shamir39 and the user's shamir39-cli fork.
// Implemented from the specification (iancoleman/shamir39/specification.md)
// and wire-compatible with the reference implementation (secrets.js-style
// Shamir over GF(2^11), primitive polynomial x^11 + x^2 + 1, init(11)):
//   share = "shamir39-p1" | params words (cont-bit + 5 bits M + 5 bits O) |
//           data words (11-bit groups of the hex-padded share bit string)
// Unlike SLIP-0039 there is no checksum, no passphrase and no digest —
// the only end-to-end integrity signal is the BIP39 checksum of the result.
(function (S39) {
  const VERSION_WORD = 'shamir39-p1';
  const BITS = 11;
  const SIZE = 1 << BITS; // 2048
  const MAX = SIZE - 1; // 2047
  const PRIMITIVE = 5; // x^11 + x^2 + 1

  // exp/log tables, generator 2 (mirrors the reference implementation)
  const EXPS = new Uint16Array(SIZE);
  const LOGS = new Uint16Array(SIZE);
  {
    let x = 1;
    for (let i = 0; i < SIZE; i++) {
      EXPS[i] = x;
      LOGS[x] = i;
      x <<= 1;
      if (x >= SIZE) {
        x ^= PRIMITIVE;
        x &= MAX;
      }
    }
  }

  function gfMod(n) {
    return ((n % MAX) + MAX) % MAX;
  }

  // Horner evaluation of the coefficient polynomial at x (x != 0)
  function horner(x, coeffs) {
    const logx = LOGS[x];
    let fx = 0;
    for (let i = coeffs.length - 1; i >= 0; i--) {
      if (fx === 0) {
        fx = coeffs[i];
        continue;
      }
      fx = EXPS[(logx + LOGS[fx]) % MAX] ^ coeffs[i];
    }
    return fx;
  }

  // Lagrange interpolation at 0. Points with y == 0 contribute nothing to
  // the sum and are skipped (matching the reference implementation).
  function lagrangeAtZero(xs, ys) {
    let sum = 0;
    for (let i = 0; i < xs.length; i++) {
      if (ys[i] === 0) continue;
      let logProduct = LOGS[ys[i]];
      for (let j = 0; j < xs.length; j++) {
        if (i === j) continue;
        logProduct += LOGS[xs[j]] - LOGS[xs[i] ^ xs[j]];
      }
      sum ^= EXPS[gfMod(logProduct)];
    }
    return sum;
  }

  function defaultRandomBytes(n) {
    return S39.native.randomBytes(n);
  }

  function random11Bits(randomBytes) {
    const b = randomBytes(2);
    return ((b[0] << 8) | b[1]) & MAX;
  }

  function wordsToIndices(words) {
    return words.map((w) => {
      const idx = S39.bip39WordsIndex.get(w);
      if (idx === undefined) throw new Error(`"${w}" is not a BIP39 word`);
      return idx;
    });
  }

  // Split a bit string into 11-bit chunks from the RIGHT; the leftmost
  // chunk may be shorter. Returned leftmost-first.
  function chunkBits(bits) {
    const chunks = [];
    let end = bits.length;
    while (end > BITS) {
      chunks.unshift(parseInt(bits.slice(end - BITS, end), 2));
      end -= BITS;
    }
    chunks.unshift(parseInt(bits.slice(0, end), 2));
    return chunks;
  }

  function toBits(value, width) {
    return value.toString(2).padStart(width, '0');
  }

  // Encode M (threshold) and O (share order) into parameter words:
  // per word: 1 continuation bit, 5 bits of M, 5 bits of O.
  function encodeParams(m, o) {
    const groups = Math.max(
      Math.ceil(m.toString(2).length / 5),
      Math.ceil(o.toString(2).length / 5)
    );
    const mBits = toBits(m, groups * 5);
    const oBits = toBits(o, groups * 5);
    const words = [];
    for (let i = 0; i < groups; i++) {
      const cont = i === groups - 1 ? '0' : '1';
      const idx = parseInt(cont + mBits.slice(i * 5, i * 5 + 5) + oBits.slice(i * 5, i * 5 + 5), 2);
      words.push(S39.bip39Words[idx]);
    }
    return words;
  }

  // Parse a share's words: returns {m, o, dataIndices}
  function parseShare(words) {
    if (words.length < 3) throw new Error('share is too short');
    if (words[0] !== VERSION_WORD) {
      throw new Error(`not a Shamir39 share (expected first word "${VERSION_WORD}")`);
    }
    const indices = wordsToIndices(words.slice(1));
    let mBits = '';
    let oBits = '';
    let dataStart = -1;
    for (let i = 0; i < indices.length; i++) {
      const bits = toBits(indices[i], BITS);
      mBits += bits.slice(1, 6);
      oBits += bits.slice(6, 11);
      if (bits[0] === '0') {
        dataStart = i + 1;
        break;
      }
    }
    if (dataStart === -1) throw new Error('unterminated share parameters');
    const m = parseInt(mBits, 2);
    const o = parseInt(oBits, 2);
    if (m < 2) throw new Error('invalid share threshold');
    const dataIndices = indices.slice(dataStart);
    if (dataIndices.length === 0) throw new Error('share carries no data');
    return { m, o, dataIndices };
  }

  // Data words -> per-chunk share values (leftmost-first), replicating the
  // reference's words->bits->hex->bits round trip (truncate the bit string
  // on the left to a multiple of 4, then chunk from the right).
  function dataWordsToChunks(dataIndices) {
    let bits = dataIndices.map((i) => toBits(i, BITS)).join('');
    bits = bits.slice(bits.length - Math.floor(bits.length / 4) * 4);
    return chunkBits(bits);
  }

  /**
   * Split a BIP39 mnemonic into Shamir39 shares.
   * opts: {words: string[], threshold, count, randomBytes=CSPRNG}
   * Returns array of share mnemonic strings.
   */
  function split(opts) {
    const { words, threshold, count, randomBytes = defaultRandomBytes } = opts;
    if (!Number.isInteger(threshold) || threshold < 2) {
      throw new Error('Shamir39 requires a threshold of at least 2');
    }
    if (!Number.isInteger(count) || count < 2) throw new Error('at least 2 shares required');
    if (count > MAX) throw new Error(`at most ${MAX} shares`);
    if (threshold > count) throw new Error('threshold cannot exceed the number of shares');

    const indices = wordsToIndices(words);
    // '1' marker preserves leading zero bits across the numeric round trip
    const secretBits = '1' + indices.map((i) => toBits(i, BITS)).join('');
    const chunks = chunkBits(secretBits);

    // per chunk: random polynomial with the chunk as constant term
    const shareChunks = Array.from({ length: count }, () => []);
    for (const chunk of chunks) {
      const coeffs = [chunk];
      for (let i = 1; i < threshold; i++) coeffs.push(random11Bits(randomBytes));
      for (let x = 1; x <= count; x++) {
        shareChunks[x - 1].push(horner(x, coeffs));
      }
      coeffs.fill(0);
    }

    return shareChunks.map((yChunks, o) => {
      // bits -> hex padding -> word padding, exactly like the reference
      const yBits = yChunks.map((y) => toBits(y, BITS)).join('');
      const hexBits = yBits.padStart(Math.ceil(yBits.length / 4) * 4, '0');
      const wordBits = hexBits.padStart(Math.ceil(hexBits.length / BITS) * BITS, '0');
      const dataWords = [];
      for (let i = 0; i < wordBits.length; i += BITS) {
        dataWords.push(S39.bip39Words[parseInt(wordBits.slice(i, i + BITS), 2)]);
      }
      return [VERSION_WORD, ...encodeParams(threshold, o), ...dataWords].join(' ');
    });
  }

  function normalizeMnemonic(mnemonic) {
    return mnemonic.trim().toLowerCase().split(/\s+/);
  }

  /** Decode a single share; returns metadata or throws with a reason. */
  function inspect(mnemonic) {
    const words = normalizeMnemonic(mnemonic);
    const { m, o, dataIndices } = parseShare(words);
    return {
      scheme: 'shamir39',
      words: words.length,
      memberIndex: o,
      memberThreshold: m,
      dataWords: dataIndices.length,
    };
  }

  /**
   * Combine Shamir39 shares back into the BIP39 mnemonic.
   * opts: {mnemonics: string[]}
   * Returns {words, memberThreshold}. No passphrase, no checksum — callers
   * should verify the BIP39 checksum of the result.
   */
  function combine(opts) {
    const { mnemonics } = opts;
    if (!mnemonics || mnemonics.length === 0) throw new Error('no shares provided');

    const byOrder = new Map(); // o -> chunks (last occurrence wins, like the reference)
    let threshold = null;
    for (const mnemonic of mnemonics) {
      const { m, o, dataIndices } = parseShare(normalizeMnemonic(mnemonic));
      if (threshold === null) threshold = m;
      if (m !== threshold) throw new Error('shares disagree on the required share count');
      byOrder.set(o, dataWordsToChunks(dataIndices));
    }

    const chunkCount = byOrder.values().next().value.length;
    for (const chunks of byOrder.values()) {
      if (chunks.length !== chunkCount) {
        throw new Error('shares have different lengths and cannot be combined');
      }
    }
    if (byOrder.size < threshold) {
      throw new Error(`not enough shares: have ${byOrder.size}, need ${threshold}`);
    }

    const xs = [...byOrder.keys()].map((o) => o + 1); // x coordinate = order + 1
    const shareList = [...byOrder.values()];
    let resultBits = '';
    for (let j = 0; j < chunkCount; j++) {
      const ys = shareList.map((chunks) => chunks[j]);
      resultBits += toBits(lagrangeAtZero(xs, ys), BITS);
    }

    // strip everything through the '1' marker, then cut to whole words
    const marker = resultBits.indexOf('1');
    if (marker === -1) throw new Error('share combination failed (no marker bit — wrong or corrupted shares)');
    let secretBits = resultBits.slice(marker + 1);
    const wordCount = Math.floor(secretBits.length / BITS);
    if (wordCount === 0) throw new Error('share combination produced no data');
    secretBits = secretBits.slice(secretBits.length - wordCount * BITS);
    const words = [];
    for (let i = 0; i < wordCount; i++) {
      words.push(S39.bip39Words[parseInt(secretBits.slice(i * BITS, (i + 1) * BITS), 2)]);
    }
    return { words, memberThreshold: threshold };
  }

  S39.schemes = S39.schemes || {};
  S39.schemes.shamir39 = { split, combine, inspect, VERSION_WORD };

  /** Detect which scheme a share line belongs to ('slip39' | 'shamir39' | null). */
  S39.schemes.detect = function detect(line) {
    const words = normalizeMnemonic(line);
    if (words.length === 0) return null;
    if (words[0] === VERSION_WORD || words[0] === 'shamir39') return 'shamir39';
    if (words.every((w) => S39.slip39WordsIndex.has(w))) return 'slip39';
    return null;
  };
})(globalThis.S39 = globalThis.S39 || {});
