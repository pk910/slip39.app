'use strict';
// Session security: runtime-poisoning detection, connection monitoring and
// the secure-wipe registry.
(function (S39) {
  const { wipeBytes } = S39.util;

  // --- runtime poisoning checks -------------------------------------------
  // A malicious extension or injected script could replace crypto functions
  // to leak or weaken secrets. These checks detect *overridden* built-ins.
  // They are best-effort: code running before us could also patch
  // Function.prototype.toString, but combined with strict CSP and script
  // integrity hashes the bar is high.

  function isNative(fn) {
    try {
      if (typeof fn !== 'function') return false;
      const src = Function.prototype.toString.call(fn);
      return /\[native code\]/.test(src);
    } catch (e) {
      return false;
    }
  }

  async function runtimeChecks() {
    const checks = [];
    const add = (name, ok, detail) => checks.push({ name, ok: !!ok, detail });

    add('Secure context', globalThis.isSecureContext,
      'WebCrypto requires https://, localhost or a local file');
    add('WebCrypto available', !!(globalThis.crypto && crypto.subtle),
      'crypto.subtle is required for all key derivation');

    // toString itself must be native, otherwise the checks below prove nothing
    let toStringNative = false;
    try {
      toStringNative = /\[native code\]/.test(
        Function.prototype.toString.call(Function.prototype.toString)
      );
    } catch (e) { /* stays false */ }
    add('Function.toString unmodified', toStringNative,
      'basis for all native-code checks');

    add('crypto.getRandomValues native', globalThis.crypto && isNative(crypto.getRandomValues),
      'system randomness source');
    if (globalThis.crypto && crypto.subtle) {
      for (const method of ['digest', 'importKey', 'deriveBits', 'sign']) {
        add(`crypto.subtle.${method} native`, isNative(crypto.subtle[method]),
          'WebCrypto primitive');
      }
    }
    add('TextEncoder native', isNative(globalThis.TextEncoder),
      'string encoding used in key derivation');
    add('Uint8Array native', isNative(globalThis.Uint8Array),
      'byte buffers holding secrets');

    // the crypto references captured at load time must still be the live
    // globals — a mismatch means something swapped them after we started
    add('crypto not swapped since load',
      globalThis.crypto && crypto.getRandomValues === S39.native.rawGetRandomValues &&
        S39.nativeSubtle.matchesLive(),
      'captured references match the live globals');

    // sanity: RNG output must not repeat or be all zeros
    try {
      const a = S39.native.randomBytes(16);
      const b = S39.native.randomBytes(16);
      const differs = !S39.util.bytesEqual(a, b);
      const nonZero = a.some((v) => v !== 0) || b.some((v) => v !== 0);
      add('RNG output sane', differs && nonZero, 'two draws differ and are non-zero');
    } catch (e) {
      add('RNG output sane', false, String(e));
    }

    // a service worker could intercept and modify future loads
    try {
      if (location.protocol === 'file:') {
        add('No service worker', true, 'not applicable to local files');
      } else if (navigator.serviceWorker) {
        const regs = await navigator.serviceWorker.getRegistrations();
        add('No service worker', regs.length === 0,
          regs.length ? `${regs.length} registration(s) found — unregister them` : 'none registered');
      } else {
        add('No service worker', true, 'service workers unsupported');
      }
    } catch (e) {
      add('No service worker', true, 'not accessible in this context');
    }

    return checks;
  }

  /**
   * Deep-freeze the entire S39 namespace tree (objects, arrays, functions and
   * their prototypes), so nothing that runs later can swap an implementation
   * or patch a nested table. Typed arrays are skipped — freezing buffer views
   * throws, and no secret-bearing buffer lives on the tree. Note that Map/Set
   * internals cannot be frozen at all, which is why the wordlist indexes are
   * closure-backed objects instead of Maps.
   */
  function deepFreeze(value, seen) {
    if (value === null) return;
    const type = typeof value;
    if (type !== 'object' && type !== 'function') return;
    if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
    if (seen.has(value)) return;
    seen.add(value);
    Object.freeze(value);
    for (const key of Reflect.ownKeys(value)) {
      let child;
      try {
        child = value[key];
      } catch (e) {
        continue; // exotic getter — nothing of ours
      }
      deepFreeze(child, seen);
    }
  }

  function freezeRuntime() {
    deepFreeze(S39, new Set());
  }

  // --- connection monitoring ----------------------------------------------

  function watchConnection(callback) {
    const notify = () => callback(navigator.onLine !== false);
    addEventListener('online', notify);
    addEventListener('offline', notify);
    notify();
  }

  // --- secure wipe registry ------------------------------------------------
  // JavaScript cannot guarantee memory erasure (strings are immutable and the
  // GC may have copied buffers), but we minimize exposure: secrets live in
  // Uint8Arrays that are overwritten on wipe, and all DOM fields are cleared.
  // For maximum assurance the user should close the tab afterwards — the UI
  // says so explicitly.

  const registry = new Set();
  const wipeCallbacks = new Set();

  function track(buffer) {
    if (buffer instanceof Uint8Array) registry.add(buffer);
    return buffer;
  }

  function onWipe(callback) {
    wipeCallbacks.add(callback);
  }

  function wipeAll() {
    for (const buffer of registry) wipeBytes(buffer);
    registry.clear();
    // overwrite then clear every input/textarea and secret-bearing element
    for (const el of document.querySelectorAll('input, textarea')) {
      if (el.type === 'checkbox' || el.type === 'radio') continue;
      el.value = 'x'.repeat(Math.max(64, el.value.length));
      el.value = '';
    }
    for (const el of document.querySelectorAll('[data-secret]')) {
      el.textContent = '';
      el.replaceChildren();
    }
    for (const callback of wipeCallbacks) {
      try { callback(); } catch (e) { /* keep wiping */ }
    }
  }

  S39.security = { runtimeChecks, freezeRuntime, watchConnection, track, onWipe, wipeAll };
})(globalThis.S39 = globalThis.S39 || {});
