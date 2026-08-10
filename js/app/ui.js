'use strict';
// UI wiring. All secret-bearing DOM nodes carry data-secret so the wipe
// routine can clear them; all secret buffers are registered with
// S39.security.track().
(function (S39) {
  const { bytesToHex, wipeBytes } = S39.util;
  const { track } = S39.security;
  const $ = (id) => document.getElementById(id);

  const state = {
    collector: null,
    genWords: null,
    recWords: null,
    recScheme: null,
    activeSource: null, // 'generated' | 'split input' | 'recovered' | 'manual input'
    infoRenderedKey: null,
  };

  const SCHEME_LABELS = { slip39: 'SLIP-0039', shamir39: 'Shamir39' };

  // Prefill the Info tab's mnemonic field — the field itself is the single
  // source of truth for all Info-tab derivations.
  function setActiveMnemonic(words, source) {
    state.activeSource = source;
    state.infoRenderedKey = null; // force re-derivation on next Info view
    $('info-input').value = words.join(' ');
    updateFieldDecoy($('info-input')); // value was set programmatically — no input event
    updateInfoValidation();
  }

  // ---------- generic helpers ----------

  function renderWordGrid(listEl, words) {
    listEl.replaceChildren(...words.map((w) => {
      const li = document.createElement('li');
      li.textContent = w;
      return li;
    }));
  }

  function setValidation(el, html) {
    el.replaceChildren();
    if (html) el.append(html);
  }

  function msg(kind, text) {
    const span = document.createElement('span');
    span.className = kind;
    span.textContent = text;
    return span;
  }

  async function copyText(button, text) {
    try {
      await navigator.clipboard.writeText(text);
      flashButton(button, 'Copied ✓');
    } catch (e) {
      flashButton(button, 'Copy failed');
    }
  }

  function flashButton(button, label) {
    const original = button.textContent;
    button.textContent = label;
    setTimeout(() => { button.textContent = original; }, 1500);
  }

  // ---------- tabs ----------

  const tabShownCallbacks = {};

  function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    for (const tab of tabs) {
      tab.addEventListener('click', () => {
        for (const t of tabs) t.classList.toggle('active', t === tab);
        for (const panel of document.querySelectorAll('.tab-panel')) {
          panel.classList.toggle('hidden', panel.id !== `tab-${tab.dataset.tab}`);
        }
        if (tabShownCallbacks[tab.dataset.tab]) tabShownCallbacks[tab.dataset.tab]();
      });
    }
  }

  function switchTab(name) {
    document.querySelector(`.tab[data-tab="${name}"]`).click();
  }

  // ---------- connection status ----------

  function initConnection() {
    S39.security.watchConnection((online) => {
      const pill = $('conn-pill');
      pill.textContent = online ? '● online' : '● offline';
      pill.className = `pill ${online ? 'online' : 'offline'}`;
      $('online-warning').classList.toggle('hidden', !online);
      $('sec-conn').textContent = online
        ? 'Your device reports being ONLINE. Disconnect (airplane mode / unplug) before handling real keys.'
        : 'Your device reports being offline. Note: this signal is best-effort — verify your network is really off.';
    });
  }

  // ---------- runtime checks ----------

  function initSecurityModal() {
    const modal = $('security-modal');
    $('sec-status').addEventListener('click', () => modal.showModal());
    $('security-modal-close').addEventListener('click', () => modal.close());
    modal.addEventListener('click', (ev) => {
      if (ev.target === modal) modal.close(); // backdrop click
    });
  }

  async function initChecks() {
    const checks = await S39.security.runtimeChecks();
    const list = $('sec-checks');
    list.replaceChildren(...checks.map((c) => {
      const li = document.createElement('li');
      const mark = document.createElement('span');
      mark.className = `mark ${c.ok ? 'ok' : 'fail'}`;
      mark.textContent = c.ok ? '✓' : '✗';
      const name = document.createElement('span');
      name.textContent = c.name;
      const detail = document.createElement('span');
      detail.className = 'detail';
      detail.textContent = c.detail || '';
      li.append(mark, name, detail);
      return li;
    }));
    const failed = checks.filter((c) => !c.ok);
    const status = $('sec-status');
    if (failed.length > 0) {
      const banner = $('check-warning');
      banner.textContent =
        `⚠ ${failed.length} runtime integrity check(s) FAILED (${failed.map((c) => c.name).join(', ')}). ` +
        'A browser extension or injected script may have tampered with this session. ' +
        'Do NOT enter real secrets — click the security status below for details.';
      banner.classList.remove('hidden');
      status.textContent = `✗ ${failed.length} of ${checks.length} security checks failed — details`;
      status.classList.add('fail');
    } else {
      status.textContent = `✓ Security checks passed (${checks.length}) — details`;
      status.classList.add('ok');
    }
    return failed.length === 0;
  }

  // ---------- entropy collection ----------

  // Collect well beyond the pool size (256 bits): the SHA-256 pool keeps
  // absorbing, so 1024 credited bits re-fill it four times over.
  const ENTROPY_TARGET_BITS = 1024;

  const ENTROPY_PROMPT =
    'Move your mouse (or draw with your finger) inside this box until the bar is full';

  function updateEntropyUi() {
    const collector = state.collector;
    const bits = Math.min(collector.collectedBits, collector.targetBits);
    const pct = Math.min(100, Math.round((bits / collector.targetBits) * 100));
    $('entropy-bar').style.width = `${pct}%`;
    $('entropy-status').textContent =
      `collected ${bits} of ${collector.targetBits} bits of user entropy (${pct}%) — ` +
      'continuously mixed into a 256-bit SHA-256 pool';
    const done = collector.complete;
    $('entropy-area').classList.toggle('done', done);
    $('entropy-area-label').textContent = done
      ? '✓ enough entropy collected — extra movement adds margin'
      : ENTROPY_PROMPT;
    $('gen-btn').disabled = !done;
  }

  function createCollector() {
    state.collector = new S39.entropy.EntropyCollector(ENTROPY_TARGET_BITS);
    state.collector.onProgress = updateEntropyUi;
    updateEntropyUi();
  }

  function initEntropy() {
    const area = $('entropy-area');
    const canvas = $('entropy-canvas');
    const ctx = canvas.getContext('2d');

    // block rendering: fixed number of hex columns per row, measured from the
    // real glyph width so every row is equally long and spans the box
    const bufferLine = $('entropy-buffer-line');
    const poolLine = $('entropy-pool-line');
    let hexCols = 64;
    const measureCols = () => {
      const row = bufferLine.parentElement;
      if (row.clientWidth === 0) return; // panel hidden
      const probe = document.createElement('span');
      probe.style.visibility = 'hidden';
      probe.style.whiteSpace = 'pre';
      probe.style.display = 'inline-block'; // the block rule for viewer spans must not apply here
      probe.style.width = 'auto';
      probe.style.letterSpacing = '0';
      probe.textContent = '0'.repeat(32);
      row.append(probe);
      const charWidth = probe.getBoundingClientRect().width / 32;
      probe.remove();
      if (charWidth <= 0) return;
      const width = row.clientWidth;
      const maxCols = Math.max(16, Math.floor(width / charWidth));
      // snap to the largest even divisor of the buffer's hex length so
      // every row of the block has exactly the same width
      const totalHex = state.collector ? state.collector.buffer.length * 2 : 528;
      hexCols = maxCols;
      for (let c = maxCols; c >= 16; c--) {
        if (c % 2 === 0 && totalHex % c === 0) {
          hexCols = c;
          break;
        }
      }
      // stretch the letter spacing so each row's last glyph touches the
      // right border of the box
      const stretch = (cols) => `${(width - cols * charWidth) / Math.max(1, cols - 1)}px`;
      bufferLine.style.letterSpacing = stretch(hexCols);
      poolLine.style.letterSpacing = stretch(Math.min(64, hexCols));
    };
    const toBlock = (bytes) =>
      S39.util.bytesToHex(bytes).replace(new RegExp(`(.{${hexCols}})`, 'g'), '$1\n').trimEnd();
    const renderBuffer = () => {
      if (state.collector) bufferLine.textContent = toBlock(state.collector.buffer);
    };
    const renderPool = () => {
      if (state.collector) poolLine.textContent = toBlock(state.collector.pool);
    };

    const resize = () => {
      // no-op while the Generate panel is hidden (clientWidth is 0 then);
      // re-run on tab switch so canvas and hex block get their real size
      if (area.clientWidth > 0 && canvas.width !== area.clientWidth) {
        canvas.width = area.clientWidth;
        canvas.height = area.clientHeight;
      }
      measureCols();
      renderBuffer();
      renderPool();
    };
    resize();
    addEventListener('resize', resize);
    tabShownCallbacks.generate = resize;

    // Live view of the collection mechanics: samples overwrite the fixed-size
    // buffer left-to-right; each full pass is absorbed into the pool
    // (pool = SHA-256(pool || buffer)) without clearing the buffer, so only
    // the pool block churns on absorb. Unlike bitaddress.org (which XORs
    // samples into a rotating pool position and hashes once at the end), the
    // whole pool is re-hashed on every absorb — intentional: a SHA-256
    // sponge, at ~µs cost.
    let renderedSamples = -1;
    let renderedFlushes = -1;
    let renderedCollector = null;
    setInterval(async () => {
      const collector = state.collector;
      if (!collector) return;
      if (collector !== renderedCollector) {
        renderedCollector = collector;
        renderedSamples = -1;
        renderedFlushes = -1;
      }
      if (collector.totalSamples !== renderedSamples) {
        renderedSamples = collector.totalSamples;
        renderBuffer();
      }
      if (collector.flushCount !== renderedFlushes) {
        renderedFlushes = collector.flushCount;
        await collector.queue; // wait for the pending absorb to settle
        if (state.collector === collector) renderPool();
      }
    }, 120);

    // every pointer movement in the window feeds the pool; ACCEPTED samples
    // (one per 10 ms at most) additionally paint the visual trail inside the
    // marked area, with a gentle periodic fade so the field stays airy
    let paintedSamples = 0;
    addEventListener('pointermove', (ev) => {
      const accepted = state.collector.addPointerSample(
        Math.round(ev.clientX), Math.round(ev.clientY),
        Math.round((ev.pressure || 0) * 255)
      );
      if (!accepted) return;
      const rect = area.getBoundingClientRect();
      const x = ev.clientX - rect.left;
      const y = ev.clientY - rect.top;
      if (x >= 0 && y >= 0 && x <= rect.width && y <= rect.height) {
        paintedSamples += 1;
        if (paintedSamples % 64 === 0) {
          // fade by ERASING alpha from the trail itself — painting a dark
          // wash instead would stack up and occlude the hex display below
          ctx.globalCompositeOperation = 'destination-out';
          ctx.fillStyle = 'rgba(0, 0, 0, 0.25)';
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.globalCompositeOperation = 'source-over';
        }
        ctx.fillStyle = 'rgba(68, 147, 248, 0.6)';
        ctx.beginPath();
        ctx.arc(x, y, 2.2, 0, Math.PI * 2);
        ctx.fill();
      }
    }, { passive: true });
    addEventListener('keydown', (ev) => state.collector.addKeySample(ev.timeStamp * 7919));

    createCollector();
  }

  // ---------- generate tab ----------

  function initGenerate() {
    $('gen-btn').addEventListener('click', async () => {
      const wordCount = Number($('gen-words').value);
      const byteLen = wordCount === 12 ? 16 : 32;
      const pool = await state.collector.snapshot();
      const entropy = track(await S39.entropy.hardenedRandomBytes(byteLen, pool));
      wipeBytes(pool);
      const words = await S39.bip39.entropyToMnemonic(entropy);
      wipeBytes(entropy);
      state.genWords = words;
      setActiveMnemonic(words, 'generated');
      renderWordGrid($('gen-mnemonic'), words);
      setDecoyGrid($('gen-mnemonic').closest('.decoy-wrap'), words.length, S39.bip39Words);
      $('gen-result').classList.remove('hidden');
    });

    $('gen-copy').addEventListener('click', (ev) => {
      if (state.genWords) copyText(ev.target, state.genWords.join(' '));
    });

    $('gen-to-split').addEventListener('click', () => {
      if (!state.genWords) return;
      $('split-input').value = state.genWords.join(' ');
      $('split-input').dispatchEvent(new Event('input'));
      switchTab('split');
    });
  }

  // ---------- split tab ----------

  function parseWords(text) {
    return text.trim().toLowerCase().split(/\s+/).filter((w) => w.length > 0);
  }

  function splitScheme() {
    return $('split-scheme').value;
  }

  function initSplitConfig() {
    const countSel = $('split-count');
    const thresholdSel = $('split-threshold');

    const rebuild = () => {
      const scheme = splitScheme();
      const minCount = scheme === 'shamir39' ? 2 : 1; // shamir39 has no 1-of-1
      const prevCount = Number(countSel.value) || 3;
      countSel.replaceChildren();
      for (let i = minCount; i <= 16; i++) {
        countSel.add(new Option(String(i), String(i)));
      }
      countSel.value = String(Math.min(Math.max(prevCount, minCount), 16));

      const count = Number(countSel.value);
      const prevThreshold = Number(thresholdSel.value) || 2;
      // SLIP39 forbids 1-of-m for m > 1; shamir39 requires a threshold of 2+
      const minThreshold = scheme === 'shamir39' ? 2 : count === 1 ? 1 : 2;
      thresholdSel.replaceChildren();
      for (let i = minThreshold; i <= count; i++) {
        thresholdSel.add(new Option(String(i), String(i)));
      }
      thresholdSel.value = String(Math.min(Math.max(prevThreshold, minThreshold), count));
    };

    countSel.addEventListener('change', rebuild);
    $('split-scheme').addEventListener('change', () => {
      const scheme = splitScheme();
      $('split-slip39-options').classList.toggle('hidden', scheme !== 'slip39');
      $('split-scheme-hint').textContent = scheme === 'slip39'
        ? 'SLIP-0039 shares carry per-share checksums and a cross-share digest and are ' +
          'compatible with Trezor and other SLIP-0039 implementations.'
        : '⚠ Shamir39 is a legacy format (iancoleman.io/shamir39). Its shares carry no ' +
          'checksum or integrity data — a mistyped word is only caught indirectly. ' +
          'Prefer SLIP-0039 for new backups.';
      rebuild();
    });
    countSel.value = '3';
    rebuild();
  }

  async function validateSplitInput() {
    const el = $('split-validation');
    const words = parseWords($('split-input').value);
    $('split-btn').disabled = true;
    if (words.length === 0) { setValidation(el, null); return; }
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      setValidation(el, msg('err', `${words.length} words — a BIP39 mnemonic has 12, 15, 18, 21 or 24`));
      return;
    }
    const unknown = words.filter((w) => !S39.bip39WordsIndex.has(w));
    if (unknown.length > 0) {
      setValidation(el, msg('err', `not in the BIP39 wordlist: ${unknown.join(', ')}`));
      return;
    }
    if (!(await S39.bip39.validateMnemonic(words))) {
      setValidation(el, msg('err', `${words.length} words, but the BIP39 checksum is invalid — check for swapped or mistyped words`));
      return;
    }
    setValidation(el, msg('ok', `✓ valid ${words.length}-word mnemonic (checksum OK)`));
    setActiveMnemonic(words, 'split input');
    $('split-btn').disabled = false;
  }

  function renderShareCard(index, total, threshold, scheme, mnemonic) {
    const card = document.createElement('div');
    card.className = 'share-card';
    const head = document.createElement('div');
    head.className = 'share-head';
    const title = document.createElement('strong');
    title.textContent = `Share ${index + 1} of ${total} — any ${threshold} recover`;
    const schemeTag = document.createElement('span');
    schemeTag.className = 'share-scheme';
    schemeTag.textContent = SCHEME_LABELS[scheme];
    title.append(schemeTag);
    const copyBtn = document.createElement('button');
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyText(copyBtn, mnemonic));
    head.append(title, copyBtn);
    const wordsEl = document.createElement('ol');
    wordsEl.className = 'word-grid';
    const words = mnemonic.split(' ');
    renderWordGrid(wordsEl, words);
    // each share card blurs and reveals individually, with its own decoy
    const wrap = document.createElement('div');
    wrap.className = 'decoy-wrap grid-wrap';
    wrap.tabIndex = 0;
    wrap.dataset.decoyContext = 'on-raised';
    wrap.append(wordsEl);
    setDecoyGrid(wrap, words.length, scheme === 'slip39' ? S39.slip39Words : S39.bip39Words);
    card.append(head, wrap);
    return card;
  }

  function initSplit() {
    $('split-input').addEventListener('input', validateSplitInput);

    $('split-btn').addEventListener('click', async () => {
      const verifyEl = $('split-verify');
      setValidation(verifyEl, msg('warn', 'splitting…'));
      try {
        const scheme = splitScheme();
        const words = parseWords($('split-input').value);
        const threshold = Number($('split-threshold').value);
        const count = Number($('split-count').value);
        const pool = await state.collector.snapshot();
        const rng = await S39.entropy.createHardenedRng(pool);
        wipeBytes(pool);

        let mnemonics;
        let okRoundtrip;
        let subset;
        if (scheme === 'slip39') {
          const passphrase = $('split-passphrase').value;
          const entropy = track(await S39.bip39.mnemonicToEntropy(words));
          mnemonics = await S39.schemes.slip39.split({
            masterSecret: entropy,
            threshold,
            count,
            passphrase,
            iterationExponent: Number($('split-exponent').value),
            extendable: $('split-extendable').checked,
            randomBytes: rng,
          });
          // self-check: recombine a random threshold-subset and compare
          subset = randomSubset(count, threshold);
          const check = await S39.schemes.slip39.combine({
            mnemonics: subset.map((i) => mnemonics[i]),
            passphrase,
          });
          okRoundtrip = S39.util.bytesEqual(check.masterSecret, entropy);
          wipeBytes(check.masterSecret);
          wipeBytes(entropy);
        } else {
          mnemonics = S39.schemes.shamir39.split({
            words,
            threshold,
            count,
            randomBytes: rng,
          });
          subset = randomSubset(count, threshold);
          const check = S39.schemes.shamir39.combine({
            mnemonics: subset.map((i) => mnemonics[i]),
          });
          okRoundtrip = check.words.join(' ') === words.join(' ');
        }
        rng.destroy();

        const result = $('split-result');
        result.replaceChildren(...mnemonics.map((m, i) => renderShareCard(i, count, threshold, scheme, m)));
        setValidation(verifyEl, okRoundtrip
          ? msg('ok', `✓ self-check passed: shares ${subset.map((i) => i + 1).sort((a, b) => a - b).join('+')} recombine to your exact mnemonic`)
          : msg('err', '✗ SELF-CHECK FAILED — do not use these shares'));
      } catch (e) {
        setValidation(verifyEl, msg('err', `✗ ${e.message}`));
      }
    });
  }

  /** Pick `k` distinct indices out of 0..n-1, CSPRNG-shuffled. */
  function randomSubset(n, k) {
    const indices = [...Array(n).keys()];
    for (let i = indices.length - 1; i > 0; i--) {
      const j = S39.native.getRandomValues(new Uint32Array(1))[0] % (i + 1);
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    return indices.slice(0, k);
  }

  // ---------- recover tab ----------

  const MAX_SHARE_INPUTS = 16;

  function shareInputRows() {
    return [...document.querySelectorAll('#rec-inputs .share-input-row')];
  }

  /** Grow a share field to fit its content (a full share spans 3+ lines). */
  function autoGrowField(field) {
    field.style.height = 'auto';
    field.style.height = `${field.scrollHeight + 2}px`;
  }

  function shareInputValues() {
    return shareInputRows().map((row) => row.querySelector('textarea').value.trim());
  }

  function createShareRow() {
    const rows = shareInputRows();
    if (rows.length >= MAX_SHARE_INPUTS) return null;
    const row = document.createElement('div');
    row.className = 'share-input-row';
    const head = document.createElement('div');
    head.className = 'share-input-head';
    const label = document.createElement('label');
    label.textContent = `Share ${rows.length + 1}`;
    const status = document.createElement('span');
    status.className = 'share-input-status';
    head.append(label, status);
    const field = document.createElement('textarea');
    field.className = 'share-field';
    field.rows = 2;
    field.autocomplete = 'off';
    field.autocapitalize = 'off';
    field.spellcheck = false;
    field.placeholder = 'share words…';
    field.addEventListener('input', () => {
      autoGrowField(field);
      onShareInput(field);
    });
    const wrap = document.createElement('div');
    wrap.className = 'decoy-wrap';
    wrap.dataset.decoyContext = 'decoy-text';
    wrap.append(field);
    row.append(head, wrap);
    $('rec-inputs').append(row);
    return row;
  }

  function ensureShareRows(count) {
    while (shareInputRows().length < Math.min(count, MAX_SHARE_INPUTS)) {
      if (!createShareRow()) break;
    }
  }

  function resetShareRows() {
    $('rec-inputs').replaceChildren();
    createShareRow();
  }

  function onShareInput(field) {
    updateFieldDecoy(field);
    // multi-line paste: distribute one share per line across the fields
    if (field.value.includes('\n')) {
      const parts = field.value.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
      field.value = parts.shift() || '';
      for (const part of parts) {
        let target = shareInputRows()
          .map((row) => row.querySelector('textarea'))
          .find((t) => t !== field && t.value.trim() === '');
        if (!target) {
          const row = createShareRow();
          if (!row) break;
          target = row.querySelector('textarea');
        }
        target.value = part;
        autoGrowField(target);
        updateFieldDecoy(target);
      }
      autoGrowField(field);
    }
    summarizeRecoverInput();
  }

  function summarizeRecoverInput() {
    const statusEl = $('rec-status');
    $('rec-btn').disabled = true;
    state.recScheme = null;
    $('rec-pass-row').classList.remove('hidden');

    const sets = new Map(); // set key -> {need, members:Set, scheme, name}
    const schemes = new Set();
    let anyFilled = false;

    for (const row of shareInputRows()) {
      const value = row.querySelector('textarea').value.trim();
      const statusSpan = row.querySelector('.share-input-status');
      row.classList.remove('ok', 'err');
      statusSpan.className = 'share-input-status';
      statusSpan.textContent = '';
      if (value === '') continue;
      anyFilled = true;
      const scheme = S39.schemes.detect(value);
      try {
        if (scheme === 'slip39') {
          const info = S39.schemes.slip39.inspect(value);
          const idHex = info.identifier.toString(16).padStart(4, '0');
          statusSpan.textContent = `✓ SLIP-0039 · share #${info.memberIndex + 1} · set ${idHex}`;
          const key = `slip39:${idHex}`;
          if (!sets.has(key)) sets.set(key, { need: info.memberThreshold, members: new Set(), scheme, name: `set ${idHex}` });
          sets.get(key).members.add(info.memberIndex);
        } else if (scheme === 'shamir39') {
          const info = S39.schemes.shamir39.inspect(value);
          statusSpan.textContent = `✓ Shamir39 · share #${info.memberIndex + 1}`;
          if (!sets.has('shamir39')) sets.set('shamir39', { need: info.memberThreshold, members: new Set(), scheme, name: 'Shamir39 set' });
          sets.get('shamir39').members.add(info.memberIndex);
        } else {
          throw new Error('not recognized as a SLIP-0039 or Shamir39 share');
        }
        schemes.add(scheme);
        row.classList.add('ok');
        statusSpan.classList.add('ok');
      } catch (e) {
        row.classList.add('err');
        statusSpan.classList.add('err');
        statusSpan.textContent = `✗ ${e.message}`;
      }
    }

    if (!anyFilled) {
      setValidation(statusEl, null);
      return;
    }

    const container = document.createElement('div');
    for (const set of sets.values()) {
      const have = set.members.size;
      const summary = document.createElement('div');
      summary.append(have >= set.need
        ? msg('ok', `${set.name}: ${have} of ${set.need} required shares — ready to recover`)
        : msg('warn', `${set.name}: ${have} of ${set.need} required shares — add ${set.need - have} more`));
      container.append(summary);
    }
    if (schemes.size > 1 || sets.size > 1) {
      container.append(msg('err', 'shares from different sets/formats cannot be combined'));
    }
    setValidation(statusEl, container);

    // once the required count is known, offer exactly that many fields
    if (sets.size === 1) {
      ensureShareRows(sets.values().next().value.need);
    }

    const ready = sets.size === 1 && schemes.size === 1 &&
      sets.values().next().value.members.size >= sets.values().next().value.need;
    if (ready) {
      state.recScheme = schemes.values().next().value;
      // Shamir39 has no passphrase concept — hide the SLIP39 passphrase field
      $('rec-pass-row').classList.toggle('hidden', state.recScheme === 'shamir39');
      $('rec-btn').disabled = false;
    }
  }

  function initRecover() {
    resetShareRows();

    $('rec-btn').addEventListener('click', async () => {
      const integrityEl = $('rec-integrity');
      try {
        const mnemonics = shareInputValues().filter((v) => v.length > 0);
        const container = document.createElement('div');
        const addLine = (node) => { container.append(node, document.createElement('br')); };
        let words;

        if (state.recScheme === 'shamir39') {
          const result = S39.schemes.shamir39.combine({ mnemonics });
          words = result.words;
          addLine(msg('ok', `✓ combined ${result.memberThreshold}-of-n Shamir39 shares`));
          addLine(msg('warn', '⚠ Shamir39 shares carry no cryptographic integrity data — ' +
            'the checks below are the only safety net'));
          if (await S39.bip39.validateMnemonic(words)) {
            addLine(msg('ok', `✓ result is a valid ${words.length}-word BIP39 mnemonic (checksum OK)`));
          } else {
            addLine(msg('err', '✗ the result has an INVALID BIP39 checksum — a share is likely ' +
              'wrong, mistyped or from a different set'));
          }
        } else {
          const result = await S39.schemes.slip39.combine({
            mnemonics,
            passphrase: $('rec-passphrase').value,
          });
          track(result.masterSecret);
          words = await S39.bip39.entropyToMnemonic(result.masterSecret);
          wipeBytes(result.masterSecret);
          addLine(msg('ok', '✓ RS1024 checksum valid on every share'));
          addLine(result.memberThreshold > 1
            ? msg('ok', '✓ SLIP-0039 digest verified — the shares are consistent and complete')
            : msg('warn', '– SLIP-0039 digest not applicable (1-of-1 share)'));
          if ($('rec-passphrase').value) {
            addLine(msg('warn',
              '⚠ a SLIP39 passphrase was applied — a wrong passphrase yields a different (valid-looking) mnemonic; verify the addresses below'));
          } else {
            addLine(msg('ok', `✓ recovered ${words.length}-word mnemonic (set ${result.identifier.toString(16).padStart(4, '0')})`));
          }
        }

        state.recWords = words;
        setActiveMnemonic(words, 'recovered');
        renderWordGrid($('rec-mnemonic'), words);
        setDecoyGrid($('rec-mnemonic').closest('.decoy-wrap'), words.length, S39.bip39Words);
        setValidation(integrityEl, container);
        $('rec-result').classList.remove('hidden');
      } catch (e) {
        setValidation(integrityEl, msg('err', `✗ ${e.message}`));
        $('rec-result').classList.remove('hidden');
        $('rec-mnemonic').replaceChildren();
      }
    });

    $('rec-copy').addEventListener('click', (ev) => {
      if (state.recWords) copyText(ev.target, state.recWords.join(' '));
    });

    // the recovered mnemonic is the active mnemonic — the Info tab derives it
    $('rec-derive').addEventListener('click', () => switchTab('info'));
  }

  // ---------- info tab ----------

  // inline SVG icons (feather-style, stroke = currentColor)
  const SVG_ATTRS = 'viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"';
  const COPY_SVG = `<svg ${SVG_ATTRS}><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>` +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
  const CHECK_SVG = `<svg ${SVG_ATTRS}><polyline points="20 6 9 17 4 12"></polyline></svg>`;
  const CROSS_SVG = `<svg ${SVG_ATTRS}><line x1="18" y1="6" x2="6" y2="18"></line>` +
    '<line x1="6" y1="6" x2="18" y2="18"></line></svg>';

  /** Small inline copy button (icon only, flashes ✓/✗). */
  function iconCopyButton(text) {
    const btn = document.createElement('button');
    btn.className = 'icon-btn';
    btn.title = 'Copy';
    btn.innerHTML = COPY_SVG;
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(text);
        btn.innerHTML = CHECK_SVG;
      } catch (e) {
        btn.innerHTML = CROSS_SVG;
      }
      setTimeout(() => { btn.innerHTML = COPY_SVG; }, 1200);
    });
    return btn;
  }

  function infoAddressTable(addresses) {
    const wrap = document.createElement('div');
    wrap.className = 'addr-table-wrap';
    const table = document.createElement('table');
    table.className = 'addr-table';
    const head = table.createTHead().insertRow();
    for (const h of ['Path', 'Address']) {
      const th = document.createElement('th');
      th.textContent = h;
      head.append(th);
    }
    const body = table.createTBody();
    for (const a of addresses) {
      const row = body.insertRow();
      const pathCell = row.insertCell();
      pathCell.textContent = a.path;
      pathCell.className = 'addr';
      const addrCell = row.insertCell();
      addrCell.className = 'addr';
      addrCell.append(document.createTextNode(a.address), iconCopyButton(a.address));
    }
    wrap.append(table);
    return wrap;
  }

  /**
   * Validate the Info tab's mnemonic field.
   * Returns {words} when usable (possibly with a checksum warning shown),
   * or null when empty/unusable.
   */
  async function updateInfoValidation() {
    const el = $('info-validation');
    const words = parseWords($('info-input').value);
    if (words.length === 0) {
      setValidation(el, null);
      return null;
    }
    if (![12, 15, 18, 21, 24].includes(words.length)) {
      setValidation(el, msg('err', `${words.length} words — a BIP39 mnemonic has 12, 15, 18, 21 or 24`));
      return null;
    }
    const unknown = words.filter((w) => !S39.bip39WordsIndex.has(w));
    if (unknown.length > 0) {
      setValidation(el, msg('err', `not in the BIP39 wordlist: ${unknown.join(', ')}`));
      return null;
    }
    if (!(await S39.bip39.validateMnemonic(words))) {
      setValidation(el, msg('warn',
        '⚠ BIP39 checksum invalid — derivation still works, but double-check the words'));
      return { words };
    }
    setValidation(el, msg('ok', `✓ valid ${words.length}-word mnemonic (checksum OK)`));
    return { words };
  }

  async function renderInfo(force) {
    const contentEl = $('info-content');
    const activeEl = $('info-active');
    const input = await updateInfoValidation();
    if (!input) {
      activeEl.textContent =
        'No mnemonic yet — generate, split or recover one (it is prefilled here), or paste one above.';
      contentEl.replaceChildren();
      $('info-custom-result').replaceChildren();
      state.infoRenderedKey = null;
      return;
    }
    activeEl.textContent =
      `Deriving from ${input.words.length} words (source: ${state.activeSource || 'manual input'})` +
      ($('info-passphrase').value ? ' + BIP39 passphrase' : '');
    const key = input.words.join(' ') + '\n' + $('info-passphrase').value;
    if (!force && state.infoRenderedKey === key) return;

    contentEl.replaceChildren(msg('warn', 'deriving…'));
    const seed = track(await S39.bip39.mnemonicToSeed(input.words, $('info-passphrase').value));
    const sections = await S39.wallet.deriveWalletInfo(seed);
    wipeBytes(seed);

    contentEl.replaceChildren(...sections.map((section) => {
      const el = document.createElement('div');
      el.className = 'info-section';
      const headRow = document.createElement('div');
      headRow.className = 'info-head';
      const h = document.createElement('h3');
      h.textContent = section.label;
      headRow.append(h);
      if (section.xpub) {
        headRow.append(xpubKindTag(`${section.xpubKind} · ${section.accountPath}`));
      }
      el.append(headRow);
      if (section.xpub) el.append(xpubValueLine(section.xpub));
      el.append(infoAddressTable(section.addresses));
      return el;
    }));
    state.infoRenderedKey = key;
  }

  // ---------- privacy decoys ----------
  // While an area is blurred, the DOM displays same-shape GARBAGE instead of
  // the real content — de-blurring a screenshot therefore yields nothing.
  // The real content is only put on screen while the area is hovered,
  // focused, or explicitly tapped (touch devices cannot hover, and iOS does
  // not focus tabindex'd divs on tap, hence the explicit "revealed" state).

  const REVEAL_HINT = matchMedia('(hover: hover)').matches ? 'hover to view' : 'tap to view';

  function randomWords(count, list) {
    const rnd = S39.native.randomBytes(count * 2);
    const out = [];
    for (let i = 0; i < count; i++) {
      out.push(list[((rnd[2 * i] << 8) | rnd[2 * i + 1]) % list.length]);
    }
    return out;
  }

  /** Word-for-word decoy of a mnemonic/share, drawn from the matching wordlist. */
  function decoyMnemonicText(value) {
    const words = value.trim().split(/\s+/);
    const isShamir39 = words[0] === S39.schemes.shamir39.VERSION_WORD;
    const list = !isShamir39 && words.every((w) => S39.slip39WordsIndex.has(w))
      ? S39.slip39Words
      : S39.bip39Words;
    const decoys = randomWords(words.length, list);
    if (isShamir39) decoys[0] = words[0]; // keep the version token plausible
    return decoys.join(' ');
  }

  /** Get/create the decoy layer (+ reveal hint) of a wrap. */
  function ensureDecoy(wrap, contextClass) {
    let decoy = wrap.querySelector(':scope > .decoy');
    if (!decoy) {
      decoy = document.createElement('div');
      decoy.className = `decoy ${contextClass || ''}`;
      decoy.setAttribute('aria-hidden', 'true');
      decoy.setAttribute('data-secret', '');
      const hint = document.createElement('span');
      hint.className = 'decoy-hint';
      hint.textContent = REVEAL_HINT;
      wrap.append(decoy, hint);
    }
    return decoy;
  }

  /** Wrap an existing element in a decoy container (keeps its DOM id usable). */
  function wrapInDecoy(el, contextClass) {
    const wrap = document.createElement('div');
    wrap.className = 'decoy-wrap';
    wrap.dataset.decoyContext = contextClass || '';
    wrap.tabIndex = 0;
    el.replaceWith(wrap);
    wrap.append(el);
    return wrap;
  }

  /** Fill a wrap's decoy with a garbage word grid and activate it. */
  function setDecoyGrid(wrap, wordCount, list) {
    const decoy = ensureDecoy(wrap, wrap.dataset.decoyContext);
    const ol = document.createElement('ol');
    ol.className = 'word-grid';
    renderWordGrid(ol, randomWords(wordCount, list));
    decoy.replaceChildren(ol);
    wrap.classList.add('active');
  }

  /** Update the decoy overlay of a wrapped input field. */
  function updateFieldDecoy(field) {
    const wrap = field.closest('.decoy-wrap');
    if (!wrap) return;
    const value = field.value.trim();
    if (value === '') {
      wrap.classList.remove('active');
      return;
    }
    // the garbage text lives in a child element: only the content is blurred,
    // the overlay box itself stays opaque and covers the field completely
    const inner = document.createElement('div');
    inner.textContent = decoyMnemonicText(value);
    ensureDecoy(wrap, wrap.dataset.decoyContext).replaceChildren(inner);
    wrap.classList.add('active');
  }

  function initDecoys() {
    // static wraps: result grids and the two mnemonic inputs
    wrapInDecoy($('gen-mnemonic'), 'on-raised').classList.add('grid-wrap');
    wrapInDecoy($('rec-mnemonic'), 'on-raised').classList.add('grid-wrap');
    for (const id of ['split-input', 'info-input']) {
      const field = $(id);
      wrapInDecoy(field, 'decoy-text');
      field.addEventListener('input', () => updateFieldDecoy(field));
    }
    // touch/tap reveal: tapping a blurred area reveals it, tapping anywhere
    // else re-hides all revealed areas
    document.addEventListener('pointerdown', (ev) => {
      const wrap = ev.target.closest ? ev.target.closest('.decoy-wrap') : null;
      for (const revealed of document.querySelectorAll('.decoy-wrap.revealed')) {
        if (revealed !== wrap) revealed.classList.remove('revealed');
      }
      if (wrap && wrap.classList.contains('active')) wrap.classList.add('revealed');
    });
    // re-mask everything the moment the window loses focus: a resting cursor
    // keeps :hover alive while unfocused, so a capture triggered from another
    // window could otherwise catch a revealed secret
    const onFocusChange = () => {
      const unfocused = !document.hasFocus() || document.hidden;
      document.body.classList.toggle('unfocused', unfocused);
      if (unfocused) {
        for (const wrap of document.querySelectorAll('.decoy-wrap.revealed')) {
          wrap.classList.remove('revealed');
        }
      }
    };
    addEventListener('blur', onFocusChange);
    addEventListener('focus', onFocusChange);
    document.addEventListener('visibilitychange', onFocusChange);

    // decoys hold garbage, but clear them on wipe anyway
    S39.security.onWipe(() => {
      for (const wrap of document.querySelectorAll('.decoy-wrap')) {
        wrap.classList.remove('active', 'revealed');
      }
    });
  }

  function xpubKindTag(label) {
    const kind = document.createElement('span');
    kind.className = 'xpub-kind';
    kind.textContent = label;
    return kind;
  }

  /** The full key in its own box, with the copy icon beside it (outside the box). */
  function xpubValueLine(xpub) {
    const line = document.createElement('div');
    line.className = 'xpub-line';
    const full = document.createElement('div');
    full.className = 'xpub-full';
    full.textContent = xpub;
    line.append(full, iconCopyButton(xpub));
    return line;
  }

  async function resolveCustomPath() {
    const validationEl = $('info-custom-validation');
    const resultEl = $('info-custom-result');
    resultEl.replaceChildren();
    const input = await updateInfoValidation();
    if (!input) {
      setValidation(validationEl, msg('err', 'enter a mnemonic above first'));
      return;
    }
    const path = $('info-custom-path').value.trim();
    if (!/^m(\/\d+['h]?)*$/.test(path)) {
      setValidation(validationEl, msg('err',
        `invalid path — expected something like m/44'/0'/0'/0 (use ' or h for hardened)`));
      return;
    }
    setValidation(validationEl, msg('warn', 'deriving…'));
    try {
      const seed = track(await S39.bip39.mnemonicToSeed(input.words, $('info-passphrase').value));
      const result = await S39.wallet.deriveCustomPath(seed, path, $('info-custom-type').value);
      wipeBytes(seed);

      resultEl.replaceChildren();
      if (result.xpub) {
        const head = document.createElement('div');
        head.className = 'xpub-head';
        head.append(xpubKindTag(`${result.xpubKind} · ${path}`));
        resultEl.append(head, xpubValueLine(result.xpub));
      }
      resultEl.append(infoAddressTable(result.rows));
      setValidation(validationEl, null);
    } catch (e) {
      setValidation(validationEl, msg('err', `✗ ${e.message}`));
    }
  }

  function initInfo() {
    tabShownCallbacks.info = () => { renderInfo(false); };
    $('info-derive').addEventListener('click', () => renderInfo(true));
    $('info-input').addEventListener('input', () => {
      state.activeSource = null; // manual edit
      state.infoRenderedKey = null;
      updateInfoValidation();
    });
    $('info-custom-resolve').addEventListener('click', resolveCustomPath);
    $('info-custom-path').addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') resolveCustomPath();
    });
    renderInfo(false);
  }

  // ---------- wipe ----------

  function wipeSession() {
    S39.security.wipeAll();
    state.genWords = null;
    state.recWords = null;
    state.recScheme = null;
    state.activeSource = null;
    state.infoRenderedKey = null;
    resetShareRows();
    setValidation($('info-validation'), null);
    setValidation($('info-custom-validation'), null);
    renderInfo(false);
    $('gen-result').classList.add('hidden');
    $('rec-result').classList.add('hidden');
    setValidation($('split-validation'), null);
    setValidation($('split-verify'), null);
    setValidation($('rec-status'), null);
    setValidation($('rec-integrity'), null);
    $('split-btn').disabled = true;
    $('rec-btn').disabled = true;
    // restart entropy collection from scratch
    if (state.collector) state.collector.destroy();
    createCollector();
    const canvas = $('entropy-canvas');
    canvas.getContext('2d').clearRect(0, 0, canvas.width, canvas.height);
  }

  // ---------- boot ----------

  document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initConnection();
    initEntropy();
    initGenerate();
    initSplitConfig();
    initSplit();
    initRecover();
    initDecoys();
    initInfo();
    initSecurityModal();
    $('intro-start').addEventListener('click', () => switchTab('generate'));
    $('privacy-toggle').addEventListener('change', (ev) => {
      document.body.classList.toggle('privacy', ev.target.checked);
    });
    $('wipe-btn').addEventListener('click', wipeSession);
    $('wipe-btn-2').addEventListener('click', wipeSession);
    addEventListener('pagehide', () => S39.security.wipeAll());
    await initChecks();
  });

  // Deep-freeze the whole S39 tree synchronously at load time — this is the
  // last script, so from here on no code can swap or patch any S39 API.
  S39.security.freezeRuntime();
})(globalThis.S39 = globalThis.S39 || {});
