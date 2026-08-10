'use strict';
// High-level SLIP-0039 API. This is the pluggable "scheme" interface —
// a future shamir39 scheme can register alongside with the same shape:
// split(), combine(), inspect().
(function (S39) {
  const { utf8ToBytes, wipeBytes, bytesEqual } = S39.util;

  function defaultRandomBytes(n) {
    return S39.native.randomBytes(n);
  }

  function checkPassphrase(passphrase) {
    for (const ch of passphrase) {
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) {
        throw new Error('SLIP39 passphrases may only contain printable ASCII characters');
      }
    }
  }

  function normalizeMnemonic(mnemonic) {
    return mnemonic.trim().toLowerCase().split(/\s+/);
  }

  /**
   * Split a master secret into a single-group n-of-m SLIP39 share set.
   * opts: {masterSecret: Uint8Array (16 or 32 bytes for 12/24-word BIP39),
   *        threshold, count, passphrase='', iterationExponent=1,
   *        extendable=false, randomBytes=CSPRNG}
   * Returns array of share mnemonic strings.
   */
  async function split(opts) {
    const {
      masterSecret,
      threshold,
      count,
      passphrase = '',
      iterationExponent = 1,
      extendable = false,
      randomBytes = defaultRandomBytes,
    } = opts;
    if (masterSecret.length < 16 || masterSecret.length % 2 !== 0) {
      throw new Error('master secret must be at least 16 bytes and of even length');
    }
    if (!Number.isInteger(threshold) || !Number.isInteger(count) || threshold < 1 || count < 1) {
      throw new Error('invalid threshold or share count');
    }
    if (threshold > count) throw new Error('threshold cannot exceed the number of shares');
    if (count > 16) throw new Error('at most 16 shares are supported');
    if (threshold === 1 && count > 1) {
      throw new Error(
        'a 1-of-m split is not allowed by SLIP39 — with threshold 1 every share alone reveals ' +
          'the secret; store copies of a 1-of-1 share instead'
      );
    }
    checkPassphrase(passphrase);

    const idBytes = randomBytes(2);
    const identifier = ((idBytes[0] << 8) | idBytes[1]) & S39.slip39share.MAX_ID;
    const ems = await S39.slip39cipher.encrypt(
      masterSecret,
      utf8ToBytes(passphrase),
      iterationExponent,
      identifier,
      extendable
    );

    // single group: group threshold 1, group count 1
    const groupShares = await S39.slip39shamir.splitSecret(1, 1, ems, randomBytes);
    const memberShares = await S39.slip39shamir.splitSecret(
      threshold,
      count,
      groupShares[0].data,
      randomBytes
    );

    const mnemonics = memberShares.map((share) =>
      S39.slip39share
        .encodeShare({
          identifier,
          extendable,
          iterationExponent,
          groupIndex: 0,
          groupThreshold: 1,
          groupCount: 1,
          memberIndex: share.x,
          memberThreshold: threshold,
          value: share.data,
        })
        .join(' ')
    );

    for (const s of groupShares) wipeBytes(s.data);
    for (const s of memberShares) wipeBytes(s.data);
    wipeBytes(ems);
    return mnemonics;
  }

  /** Decode a single share mnemonic; returns metadata or throws with a reason. */
  function inspect(mnemonic) {
    const words = normalizeMnemonic(mnemonic);
    const share = S39.slip39share.decodeShare(words);
    const info = {
      words: words.length,
      identifier: share.identifier,
      extendable: share.extendable,
      iterationExponent: share.iterationExponent,
      groupIndex: share.groupIndex,
      groupThreshold: share.groupThreshold,
      groupCount: share.groupCount,
      memberIndex: share.memberIndex,
      memberThreshold: share.memberThreshold,
      secretBytes: share.value.length,
    };
    wipeBytes(share.value);
    return info;
  }

  /**
   * Combine share mnemonics and recover the master secret.
   * opts: {mnemonics: string[], passphrase=''}
   * Returns {masterSecret, identifier, extendable, iterationExponent,
   *          groupThreshold, memberThreshold}.
   */
  async function combine(opts) {
    const { mnemonics, passphrase = '' } = opts;
    checkPassphrase(passphrase);
    if (!mnemonics || mnemonics.length === 0) throw new Error('no shares provided');

    const shares = mnemonics.map((m) => S39.slip39share.decodeShare(normalizeMnemonic(m)));
    const first = shares[0];
    for (const s of shares) {
      if (
        s.identifier !== first.identifier ||
        s.extendable !== first.extendable ||
        s.iterationExponent !== first.iterationExponent ||
        s.groupThreshold !== first.groupThreshold ||
        s.groupCount !== first.groupCount ||
        s.value.length !== first.value.length
      ) {
        throw new Error('the shares belong to different share sets and cannot be combined');
      }
    }

    // group by group index, dedupe by member index
    const groups = new Map();
    for (const s of shares) {
      if (!groups.has(s.groupIndex)) groups.set(s.groupIndex, new Map());
      const members = groups.get(s.groupIndex);
      const existing = members.get(s.memberIndex);
      if (existing) {
        if (!bytesEqual(existing.value, s.value)) {
          throw new Error(`two different shares with the same member index #${s.memberIndex + 1}`);
        }
        continue; // exact duplicate share, ignore
      }
      if (members.size > 0 && s.memberThreshold !== members.values().next().value.memberThreshold) {
        throw new Error('shares in the same group disagree on the member threshold');
      }
      members.set(s.memberIndex, s);
    }

    // recover each complete group's secret
    const groupShares = [];
    let memberThreshold = null;
    for (const [groupIndex, members] of groups) {
      const need = members.values().next().value.memberThreshold;
      if (memberThreshold === null) memberThreshold = need;
      if (members.size < need) {
        throw new Error(
          `not enough shares: group ${groupIndex + 1} has ${members.size} of ${need} required shares`
        );
      }
      const use = [...members.values()].slice(0, need).map((s) => ({ x: s.memberIndex, data: s.value }));
      groupShares.push({
        x: groupIndex,
        data: await S39.slip39shamir.recoverSecret(need, use),
      });
    }

    if (groupShares.length < first.groupThreshold) {
      throw new Error(
        `not enough share groups: have ${groupShares.length}, need ${first.groupThreshold}`
      );
    }

    const ems = await S39.slip39shamir.recoverSecret(
      first.groupThreshold,
      groupShares.slice(0, first.groupThreshold)
    );
    const masterSecret = await S39.slip39cipher.decrypt(
      ems,
      utf8ToBytes(passphrase),
      first.iterationExponent,
      first.identifier,
      first.extendable
    );

    wipeBytes(ems);
    for (const g of groupShares) wipeBytes(g.data);
    for (const s of shares) wipeBytes(s.value);

    return {
      masterSecret,
      identifier: first.identifier,
      extendable: first.extendable,
      iterationExponent: first.iterationExponent,
      groupThreshold: first.groupThreshold,
      memberThreshold,
    };
  }

  S39.schemes = S39.schemes || {};
  S39.schemes.slip39 = { split, combine, inspect };
})(globalThis.S39 = globalThis.S39 || {});
