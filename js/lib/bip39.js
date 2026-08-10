'use strict';
// BIP-0039 mnemonic encoding (English wordlist only).
// Implemented from the specification:
// https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039.mediawiki
// Verified against the Trezor reference test vectors in the test suite.
(function (S39) {
  const { concatBytes, utf8ToBytes, wipeBytes } = S39.util;

  function checksumBits(entropyLen) {
    return (entropyLen * 8) / 32;
  }

  /** entropy (16 or 32 bytes) -> array of words */
  async function entropyToMnemonic(entropy) {
    if (![16, 20, 24, 28, 32].includes(entropy.length)) {
      throw new Error('entropy must be 16-32 bytes in 4-byte steps');
    }
    const csBits = checksumBits(entropy.length);
    const hash = await S39.hash.sha256(entropy);
    const totalBits = entropy.length * 8 + csBits;
    const words = [];
    for (let i = 0; i < totalBits / 11; i++) {
      let idx = 0;
      for (let bit = i * 11; bit < (i + 1) * 11; bit++) {
        const byte = bit < entropy.length * 8 ? entropy[bit >> 3] : hash[(bit - entropy.length * 8) >> 3];
        const srcBit = bit < entropy.length * 8 ? bit : bit - entropy.length * 8;
        idx = (idx << 1) | ((byte >> (7 - (srcBit & 7))) & 1);
      }
      words.push(S39.bip39Words[idx]);
    }
    wipeBytes(hash);
    return words;
  }

  /** array of words -> entropy bytes; throws on bad word or checksum */
  async function mnemonicToEntropy(words) {
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      throw new Error('mnemonic must be 12, 15, 18, 21 or 24 words');
    }
    const indices = words.map((w) => {
      const idx = S39.bip39WordsIndex.get(w);
      if (idx === undefined) throw new Error(`"${w}" is not a BIP39 word`);
      return idx;
    });
    const totalBits = words.length * 11;
    const entBits = totalBits - Math.floor(totalBits / 33);
    const entropy = new Uint8Array(entBits / 8);
    let checksum = 0;
    for (let bit = 0; bit < totalBits; bit++) {
      const wordBit = (indices[Math.floor(bit / 11)] >> (10 - (bit % 11))) & 1;
      if (bit < entBits) {
        if (wordBit) entropy[bit >> 3] |= 0x80 >> (bit & 7);
      } else {
        checksum = (checksum << 1) | wordBit;
      }
    }
    const hash = await S39.hash.sha256(entropy);
    const expected = hash[0] >> (8 - (totalBits - entBits));
    wipeBytes(hash);
    if (checksum !== expected) {
      wipeBytes(entropy);
      throw new Error('invalid BIP39 checksum');
    }
    return entropy;
  }

  async function validateMnemonic(words) {
    try {
      const entropy = await mnemonicToEntropy(words);
      wipeBytes(entropy);
      return true;
    } catch (e) {
      return false;
    }
  }

  /** mnemonic words + optional passphrase -> 64-byte BIP39 seed */
  async function mnemonicToSeed(words, passphrase) {
    const mnemonic = utf8ToBytes(words.join(' ').normalize('NFKD'));
    const salt = utf8ToBytes('mnemonic' + (passphrase || '').normalize('NFKD'));
    const seed = await S39.hash.pbkdf2Sha512(mnemonic, salt, 2048, 64);
    wipeBytes(mnemonic);
    return seed;
  }

  S39.bip39 = { entropyToMnemonic, mnemonicToEntropy, validateMnemonic, mnemonicToSeed };
})(globalThis.S39 = globalThis.S39 || {});
