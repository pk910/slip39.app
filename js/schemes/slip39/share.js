'use strict';
// SLIP-0039 share mnemonic encoding/decoding (10-bit words).
// Layout: id(15) ext(1) e(4) | GI(4) Gt-1(4) g-1(4) | I(4) t-1(4) | value | checksum(3 words)
(function (S39) {
  const RADIX_BITS = 10;
  const ID_BITS = 15;
  const METADATA_WORDS = 7; // 4 prefix words + 3 checksum words
  const MIN_STRENGTH_BITS = 128;
  const MIN_MNEMONIC_WORDS = METADATA_WORDS + Math.ceil(MIN_STRENGTH_BITS / RADIX_BITS);
  const CUSTOMIZATION = 'shamir';
  const CUSTOMIZATION_EXTENDABLE = 'shamir_extendable';
  const MAX_ID = (1 << ID_BITS) - 1;

  function customization(extendable) {
    return extendable ? CUSTOMIZATION_EXTENDABLE : CUSTOMIZATION;
  }

  /**
   * Encode share parameters to a mnemonic (array of words).
   * params: {identifier, extendable, iterationExponent, groupIndex,
   *          groupThreshold, groupCount, memberIndex, memberThreshold, value}
   */
  function encodeShare(params) {
    const p = params;
    if (p.identifier < 0 || p.identifier > MAX_ID) throw new Error('invalid identifier');
    if (p.iterationExponent < 0 || p.iterationExponent > 15) throw new Error('invalid iteration exponent');
    for (const v of [p.groupIndex, p.groupThreshold - 1, p.groupCount - 1, p.memberIndex, p.memberThreshold - 1]) {
      if (!Number.isInteger(v) || v < 0 || v > 15) throw new Error('invalid share parameter');
    }
    const words = [
      p.identifier >>> 5,
      ((p.identifier & 0x1f) << 5) | ((p.extendable ? 1 : 0) << 4) | p.iterationExponent,
      (p.groupIndex << 6) | ((p.groupThreshold - 1) << 2) | ((p.groupCount - 1) >>> 2),
      (((p.groupCount - 1) & 3) << 8) | (p.memberIndex << 4) | (p.memberThreshold - 1),
    ];

    // value: front-padded with zero bits to a multiple of 10
    const valueBits = p.value.length * 8;
    const valueWords = Math.ceil(valueBits / RADIX_BITS);
    let acc = 0n;
    for (const byte of p.value) acc = (acc << 8n) | BigInt(byte);
    for (let i = valueWords - 1; i >= 0; i--) {
      words[4 + i] = Number(acc & 1023n);
      acc >>= 10n;
    }
    words.push(...S39.slip39rs1024.createChecksum(words, customization(p.extendable)));
    return words.map((w) => S39.slip39Words[w]);
  }

  /** Decode a mnemonic (array of words) to share parameters. Throws on any error. */
  function decodeShare(words) {
    if (words.length < MIN_MNEMONIC_WORDS) {
      throw new Error(`share must have at least ${MIN_MNEMONIC_WORDS} words`);
    }
    const indices = words.map((w) => {
      const idx = S39.slip39WordsIndex.get(w);
      if (idx === undefined) throw new Error(`"${w}" is not a SLIP39 word`);
      return idx;
    });

    const identifier = (indices[0] << 5) | (indices[1] >>> 5);
    const extendable = ((indices[1] >>> 4) & 1) === 1;
    if (!S39.slip39rs1024.verifyChecksum(indices, customization(extendable))) {
      throw new Error('invalid share checksum');
    }
    const iterationExponent = indices[1] & 15;
    const groupIndex = indices[2] >>> 6;
    const groupThreshold = ((indices[2] >>> 2) & 15) + 1;
    const groupCount = (((indices[2] & 3) << 2) | (indices[3] >>> 8)) + 1;
    const memberIndex = (indices[3] >>> 4) & 15;
    const memberThreshold = (indices[3] & 15) + 1;
    if (groupCount < groupThreshold) {
      throw new Error('invalid share: group threshold larger than group count');
    }

    const valueWords = indices.length - METADATA_WORDS;
    const paddingBits = (valueWords * RADIX_BITS) % 16;
    if (paddingBits > 8) throw new Error('invalid share value length');
    let acc = 0n;
    for (let i = 0; i < valueWords; i++) acc = (acc << 10n) | BigInt(indices[4 + i]);
    const valueBits = valueWords * RADIX_BITS - paddingBits;
    if (acc >> BigInt(valueBits) !== 0n) {
      throw new Error('invalid share: padding bits are not zero');
    }
    const value = new Uint8Array(valueBits / 8);
    for (let i = value.length - 1; i >= 0; i--) {
      value[i] = Number(acc & 0xffn);
      acc >>= 8n;
    }

    return {
      identifier,
      extendable,
      iterationExponent,
      groupIndex,
      groupThreshold,
      groupCount,
      memberIndex,
      memberThreshold,
      value,
    };
  }

  S39.slip39share = { encodeShare, decodeShare, MAX_ID, MIN_MNEMONIC_WORDS };
})(globalThis.S39 = globalThis.S39 || {});
