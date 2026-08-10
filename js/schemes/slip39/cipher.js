'use strict';
// SLIP-0039 master secret encryption: a four-round Feistel network with
// PBKDF2-HMAC-SHA256 as the round function. Applies even with an empty
// passphrase (SLIP-0039 shares always carry the *encrypted* master secret).
(function (S39) {
  const { concatBytes, wipeBytes } = S39.util;
  const ROUND_COUNT = 4;
  const BASE_ITERATION_COUNT = 10000;

  function getSalt(identifier, extendable) {
    if (extendable) return new Uint8Array(0);
    const salt = new Uint8Array(8);
    salt.set(Array.from('shamir', (c) => c.charCodeAt(0)));
    salt[6] = (identifier >>> 8) & 0xff;
    salt[7] = identifier & 0xff;
    return salt;
  }

  async function roundFunction(round, passphrase, iterationExponent, salt, r) {
    const password = concatBytes(new Uint8Array([round]), passphrase);
    const fullSalt = concatBytes(salt, r);
    const iterations = (BASE_ITERATION_COUNT << iterationExponent) / ROUND_COUNT;
    const out = await S39.hash.pbkdf2Sha256(password, fullSalt, iterations, r.length);
    wipeBytes(password);
    wipeBytes(fullSalt);
    return out;
  }

  async function feistel(data, passphrase, iterationExponent, identifier, extendable, rounds) {
    if (data.length < 16 || data.length % 2 !== 0) {
      throw new Error('master secret length must be an even number of bytes, at least 16');
    }
    const salt = getSalt(identifier, extendable);
    let l = data.slice(0, data.length / 2);
    let r = data.slice(data.length / 2);
    for (const i of rounds) {
      const f = await roundFunction(i, passphrase, iterationExponent, salt, r);
      const newR = new Uint8Array(l.length);
      for (let k = 0; k < l.length; k++) newR[k] = l[k] ^ f[k];
      wipeBytes(f);
      wipeBytes(l);
      l = r;
      r = newR;
    }
    const out = concatBytes(r, l);
    wipeBytes(r);
    wipeBytes(l);
    return out;
  }

  async function encrypt(masterSecret, passphrase, iterationExponent, identifier, extendable) {
    return feistel(masterSecret, passphrase, iterationExponent, identifier, extendable, [0, 1, 2, 3]);
  }

  async function decrypt(encrypted, passphrase, iterationExponent, identifier, extendable) {
    return feistel(encrypted, passphrase, iterationExponent, identifier, extendable, [3, 2, 1, 0]);
  }

  S39.slip39cipher = { encrypt, decrypt };
})(globalThis.S39 = globalThis.S39 || {});
