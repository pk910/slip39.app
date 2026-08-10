'use strict';
// SLIP-0039 Shamir secret sharing over GF(256), including the digest share
// (index 254) that lets recovery detect wrong-but-well-formed share sets.
(function (S39) {
  const { concatBytes, bytesEqual, wipeBytes } = S39.util;
  const DIGEST_INDEX = 254;
  const SECRET_INDEX = 255;
  const DIGEST_LENGTH_BYTES = 4;
  const MAX_SHARE_COUNT = 16;

  async function createDigest(randomData, sharedSecret) {
    const mac = await S39.hash.hmacSha256(randomData, sharedSecret);
    const digest = mac.slice(0, DIGEST_LENGTH_BYTES);
    wipeBytes(mac);
    return digest;
  }

  /**
   * Split `secret` into `shareCount` shares, any `threshold` of which recover it.
   * `randomBytes(n)` supplies cryptographic randomness.
   * Returns an array of {x, data}.
   */
  async function splitSecret(threshold, shareCount, secret, randomBytes) {
    if (!Number.isInteger(threshold) || threshold < 1) throw new Error('invalid threshold');
    if (threshold > shareCount) throw new Error('threshold cannot exceed the number of shares');
    if (shareCount > MAX_SHARE_COUNT) throw new Error(`at most ${MAX_SHARE_COUNT} shares`);

    if (threshold === 1) {
      // spec: with threshold 1 every share is the secret itself
      return Array.from({ length: shareCount }, (_, i) => ({ x: i, data: Uint8Array.from(secret) }));
    }

    const randomShareCount = threshold - 2;
    const shares = [];
    for (let i = 0; i < randomShareCount; i++) {
      shares.push({ x: i, data: randomBytes(secret.length) });
    }

    const randomPart = randomBytes(secret.length - DIGEST_LENGTH_BYTES);
    const digest = await createDigest(randomPart, secret);
    const baseShares = [
      ...shares,
      { x: DIGEST_INDEX, data: concatBytes(digest, randomPart) },
      { x: SECRET_INDEX, data: secret },
    ];
    for (let i = randomShareCount; i < shareCount; i++) {
      shares.push({ x: i, data: S39.slip39gf.interpolate(baseShares, i) });
    }
    wipeBytes(digest);
    wipeBytes(randomPart);
    wipeBytes(baseShares[baseShares.length - 2].data);
    return shares;
  }

  /**
   * Recover the secret from >= threshold shares ({x, data}).
   * Verifies the SLIP-0039 digest when threshold > 1.
   */
  async function recoverSecret(threshold, shares) {
    if (threshold === 1) {
      return Uint8Array.from(shares[0].data);
    }
    const sharedSecret = S39.slip39gf.interpolate(shares, SECRET_INDEX);
    const digestShare = S39.slip39gf.interpolate(shares, DIGEST_INDEX);
    const digest = digestShare.slice(0, DIGEST_LENGTH_BYTES);
    const randomPart = digestShare.slice(DIGEST_LENGTH_BYTES);
    const expected = await createDigest(randomPart, sharedSecret);
    const ok = bytesEqual(digest, expected);
    wipeBytes(digestShare);
    wipeBytes(digest);
    wipeBytes(randomPart);
    wipeBytes(expected);
    if (!ok) {
      wipeBytes(sharedSecret);
      throw new Error('share digest verification failed — the shares are inconsistent');
    }
    return sharedSecret;
  }

  S39.slip39shamir = { splitSecret, recoverSecret, MAX_SHARE_COUNT };
})(globalThis.S39 = globalThis.S39 || {});
