'use strict';
// Address and account-xpub derivation for the active mnemonic:
// BTC BIP44 (P2PKH), BIP49 (P2SH-P2WPKH), BIP84 (P2WPKH) and Ethereum
// (BIP44, EIP-55). First two external addresses per path plus the
// account-level extended public key (xpub/ypub/zpub per SLIP-0132).
(function (S39) {
  const { bytesToHex, concatBytes, wipeBytes } = S39.util;

  async function hash160(data) {
    return S39.ripemd160(await S39.hash.sha256(data));
  }

  async function p2pkhAddress(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, true);
    const payload = concatBytes(new Uint8Array([0x00]), await hash160(pub));
    return S39.base58.encodeBase58Check(payload);
  }

  async function p2shP2wpkhAddress(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, true);
    const redeemScript = concatBytes(new Uint8Array([0x00, 0x14]), await hash160(pub));
    const payload = concatBytes(new Uint8Array([0x05]), await hash160(redeemScript));
    return S39.base58.encodeBase58Check(payload);
  }

  async function p2wpkhAddress(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, true);
    return S39.bech32.encodeSegwitV0('bc', await hash160(pub));
  }

  function ethAddress(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, false);
    const hash = S39.keccak256(pub.subarray(1));
    const lower = bytesToHex(hash.subarray(12));
    // EIP-55 checksum casing
    const caseHash = bytesToHex(S39.keccak256(new TextEncoder().encode(lower)));
    let out = '0x';
    for (let i = 0; i < lower.length; i++) {
      out += parseInt(caseHash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
    }
    return out;
  }

  // TRON: same keccak-derived 20 bytes as Ethereum, prefixed 0x41, Base58Check
  async function tronAddress(node) {
    const pub = S39.secp256k1.getPublicKey(node.privateKey, false);
    const hash = S39.keccak256(pub.subarray(1));
    const payload = concatBytes(new Uint8Array([0x41]), hash.subarray(12));
    return S39.base58.encodeBase58Check(payload);
  }

  // Solana: the address IS the base58-encoded ed25519 public key
  async function solanaAddress(edNode) {
    const pub = await S39.ed25519.getPublicKey(edNode.key);
    return S39.base58.encodeBase58(pub);
  }

  const PLANS = [
    {
      coin: 'BTC',
      label: 'Bitcoin — Legacy (BIP44 P2PKH)',
      accountPath: "m/44'/0'/0'",
      xpubKind: 'xpub',
      addressFn: p2pkhAddress,
    },
    {
      coin: 'BTC',
      label: 'Bitcoin — Wrapped SegWit (BIP49 P2SH-P2WPKH)',
      accountPath: "m/49'/0'/0'",
      xpubKind: 'ypub',
      addressFn: p2shP2wpkhAddress,
    },
    {
      coin: 'BTC',
      label: 'Bitcoin — Native SegWit (BIP84 P2WPKH)',
      accountPath: "m/84'/0'/0'",
      xpubKind: 'zpub',
      addressFn: p2wpkhAddress,
    },
    {
      coin: 'ETH',
      label: 'Ethereum (BIP44)',
      accountPath: "m/44'/60'/0'",
      xpubKind: 'xpub',
      addressFn: ethAddress,
    },
    {
      coin: 'TRX',
      label: 'TRON (BIP44 TRC-20)',
      accountPath: "m/44'/195'/0'",
      xpubKind: 'xpub',
      addressFn: tronAddress,
    },
  ];

  /**
   * Derive per-path account info from a 64-byte BIP39 seed.
   * Returns [{coin, label, accountPath, xpubKind, xpub, addresses:[{path, address}]}]
   * with the first two external addresses of each account.
   */
  async function deriveWalletInfo(seed) {
    const root = await S39.bip32.fromMasterSeed(seed);
    const sections = [];
    for (const plan of PLANS) {
      const account = await S39.bip32.derivePath(root, plan.accountPath);
      const xpub = await S39.bip32.toExtendedPublicKey(account, plan.xpubKind);
      const external = await S39.bip32.deriveChild(account, 0);
      const addresses = [];
      for (let i = 0; i < 2; i++) {
        const node = await S39.bip32.deriveChild(external, i);
        addresses.push({ path: `${plan.accountPath}/0/${i}`, address: await plan.addressFn(node) });
        S39.bip32.wipeNode(node);
      }
      S39.bip32.wipeNode(external);
      S39.bip32.wipeNode(account);
      sections.push({
        coin: plan.coin,
        label: plan.label,
        accountPath: plan.accountPath,
        xpubKind: plan.xpubKind,
        xpub,
        addresses,
      });
    }
    S39.bip32.wipeNode(root);

    // Solana: SLIP-0010 ed25519, Phantom-style account paths m/44'/501'/i'/0'.
    // No extended public key — ed25519 has no non-hardened derivation.
    const solAddresses = [];
    for (let i = 0; i < 2; i++) {
      const path = `m/44'/501'/${i}'/0'`;
      const node = await S39.slip10.derivePath(seed, path);
      solAddresses.push({ path, address: await solanaAddress(node) });
      S39.slip10.wipeNode(node);
    }
    sections.push({
      coin: 'SOL',
      label: 'Solana (SLIP-0010 ed25519)',
      accountPath: "m/44'/501'",
      xpubKind: null,
      xpub: null,
      addresses: solAddresses,
    });
    return sections;
  }

  const ADDRESS_TYPES = {
    p2pkh: { label: 'BTC Legacy (P2PKH)', xpubKind: 'xpub', fn: p2pkhAddress, curve: 'secp256k1' },
    'p2sh-p2wpkh': { label: 'BTC Wrapped SegWit (P2SH-P2WPKH)', xpubKind: 'ypub', fn: p2shP2wpkhAddress, curve: 'secp256k1' },
    p2wpkh: { label: 'BTC Native SegWit (P2WPKH)', xpubKind: 'zpub', fn: p2wpkhAddress, curve: 'secp256k1' },
    eth: { label: 'Ethereum (EIP-55)', xpubKind: 'xpub', fn: ethAddress, curve: 'secp256k1' },
    tron: { label: 'TRON (TRC-20)', xpubKind: 'xpub', fn: tronAddress, curve: 'secp256k1' },
    solana: { label: 'Solana (ed25519)', xpubKind: null, fn: solanaAddress, curve: 'ed25519' },
  };

  /**
   * Resolve an arbitrary derivation path for the given seed and address type.
   * Returns {xpubKind, xpub, rows: [{path, address}]} — the address at the
   * path itself plus its first two children (path/0, path/1 — hardened for
   * ed25519, which has no non-hardened derivation and no extended keys).
   */
  async function deriveCustomPath(seed, path, type) {
    const plan = ADDRESS_TYPES[type];
    if (!plan) throw new Error(`unknown address type "${type}"`);
    const base = path.replace(/\/$/, '');

    if (plan.curve === 'ed25519') {
      const node = await S39.slip10.derivePath(seed, path);
      const rows = [{ path, address: await solanaAddress(node) }];
      for (let i = 0; i < 2; i++) {
        const child = await S39.slip10.deriveChild(node, i);
        rows.push({ path: `${base}/${i}'`, address: await solanaAddress(child) });
        S39.slip10.wipeNode(child);
      }
      S39.slip10.wipeNode(node);
      return { xpubKind: null, xpub: null, rows };
    }

    const root = await S39.bip32.fromMasterSeed(seed);
    const node = await S39.bip32.derivePath(root, path);
    const xpub = await S39.bip32.toExtendedPublicKey(node, plan.xpubKind);
    const rows = [{ path, address: await plan.fn(node) }];
    for (let i = 0; i < 2; i++) {
      const child = await S39.bip32.deriveChild(node, i);
      rows.push({ path: `${base}/${i}`, address: await plan.fn(child) });
      S39.bip32.wipeNode(child);
    }
    if (node !== root) S39.bip32.wipeNode(node);
    S39.bip32.wipeNode(root);
    return { xpubKind: plan.xpubKind, xpub, rows };
  }

  /** Flat address list (used by the Recover tab's verification table). */
  async function deriveCommonAddresses(seed) {
    const sections = await deriveWalletInfo(seed);
    return sections.flatMap((s) =>
      s.addresses.map((a) => ({ coin: s.coin, kind: s.label, path: a.path, address: a.address }))
    );
  }

  S39.wallet = { deriveWalletInfo, deriveCommonAddresses, deriveCustomPath, ADDRESS_TYPES };
})(globalThis.S39 = globalThis.S39 || {});
