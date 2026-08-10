// Loads the app's classic scripts into the Node global scope for testing.
// The scripts are plain IIFEs that attach to globalThis.S39, exactly as in
// the browser; indirect eval executes them unmodified.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export const SCRIPT_ORDER = [
  'js/lib/util.js',
  'js/lib/webcrypto.js',
  'js/lib/keccak256.js',
  'js/lib/ripemd160.js',
  'js/lib/secp256k1.js',
  'js/lib/bech32.js',
  'js/lib/base58.js',
  'js/lib/ed25519.js',
  'js/lib/slip10.js',
  'js/lib/slip39-wordlist.js',
  'js/lib/bip39-wordlist.js',
  'js/lib/bip39.js',
  'js/lib/bip32.js',
  'js/schemes/slip39/gf256.js',
  'js/schemes/slip39/rs1024.js',
  'js/schemes/slip39/cipher.js',
  'js/schemes/slip39/shamir.js',
  'js/schemes/slip39/share.js',
  'js/schemes/slip39/index.js',
  'js/schemes/shamir39/index.js',
  'js/app/wallet.js',
  'js/app/entropy.js',
];

let loaded = false;

export function loadS39() {
  if (!loaded) {
    for (const file of SCRIPT_ORDER) {
      (0, eval)(readFileSync(path.join(root, file), 'utf8'));
    }
    loaded = true;
  }
  return globalThis.S39;
}

export function readVectors(name) {
  return JSON.parse(readFileSync(path.join(root, 'vectors', name), 'utf8'));
}
