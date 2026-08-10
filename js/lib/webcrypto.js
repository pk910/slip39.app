'use strict';
// Thin wrappers around the browser-native WebCrypto API (crypto.subtle).
// SHA-256/512, HMAC and PBKDF2 intentionally use the platform implementation:
// it is memory-safe, audited and cannot be swapped by a package manager.
(function (S39) {
  // Capture the subtle-crypto methods at load time and bind them, so a later
  // swap of globalThis.crypto or its methods cannot redirect our hashing.
  const subtleObj = globalThis.crypto && globalThis.crypto.subtle;
  const native = subtleObj
    ? Object.freeze({
        digest: subtleObj.digest.bind(subtleObj),
        importKey: subtleObj.importKey.bind(subtleObj),
        deriveBits: subtleObj.deriveBits.bind(subtleObj),
        sign: subtleObj.sign.bind(subtleObj),
      })
    : null;
  S39.nativeSubtle = Object.freeze({
    available: !!native,
    // true while the live global still is the object we captured at load
    matchesLive: () => !!subtleObj && globalThis.crypto && globalThis.crypto.subtle === subtleObj,
  });

  function subtle() {
    if (!native) {
      throw new Error(
        'WebCrypto (crypto.subtle) is unavailable. This app requires a secure context ' +
          '(https://, http://localhost or a local file).'
      );
    }
    return native;
  }

  async function sha256(data) {
    return new Uint8Array(await subtle().digest('SHA-256', data));
  }

  async function sha512(data) {
    return new Uint8Array(await subtle().digest('SHA-512', data));
  }

  async function hmac(hashName, key, message) {
    const cryptoKey = await subtle().importKey(
      'raw',
      key,
      { name: 'HMAC', hash: hashName },
      false,
      ['sign']
    );
    return new Uint8Array(await subtle().sign('HMAC', cryptoKey, message));
  }

  async function hmacSha256(key, message) {
    return hmac('SHA-256', key, message);
  }

  async function hmacSha512(key, message) {
    return hmac('SHA-512', key, message);
  }

  async function pbkdf2(hashName, password, salt, iterations, dkLen) {
    const cryptoKey = await subtle().importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle().deriveBits(
      { name: 'PBKDF2', hash: hashName, salt, iterations },
      cryptoKey,
      dkLen * 8
    );
    return new Uint8Array(bits);
  }

  async function pbkdf2Sha256(password, salt, iterations, dkLen) {
    return pbkdf2('SHA-256', password, salt, iterations, dkLen);
  }

  async function pbkdf2Sha512(password, salt, iterations, dkLen) {
    return pbkdf2('SHA-512', password, salt, iterations, dkLen);
  }

  S39.hash = { sha256, sha512, hmacSha256, hmacSha512, pbkdf2Sha256, pbkdf2Sha512 };
})(globalThis.S39 = globalThis.S39 || {});
