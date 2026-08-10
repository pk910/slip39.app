import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadS39 } from './load.mjs';

const S39 = loadS39();

function feedSamples(collector, count, seed = 1) {
  for (let i = 0; i < count; i++) {
    collector.lastSample = -1000; // bypass the 5ms rate limit for testing
    collector.addPointerSample((i * 31 + seed) % 1920, (i * 17 + seed * 3) % 1080, i & 0xff);
  }
}

test('entropy collector accumulates and mixes samples', async () => {
  const collector = new S39.entropy.EntropyCollector(128);
  assert.equal(collector.complete, false);
  feedSamples(collector, 128);
  assert.equal(collector.collectedBits, 128);
  assert.equal(collector.complete, true);

  const snapshotA = await collector.snapshot();
  assert.equal(snapshotA.length, 32);
  feedSamples(collector, 16, 99);
  const snapshotB = await collector.snapshot();
  assert.notDeepEqual(Array.from(snapshotA), Array.from(snapshotB), 'pool must evolve with new samples');
  collector.destroy();
});

test('identical pointer positions and rapid samples are not credited', () => {
  const collector = new S39.entropy.EntropyCollector(128);
  collector.lastSample = -1000;
  collector.addPointerSample(100, 100, 0);
  assert.equal(collector.collectedBits, 1);
  collector.addPointerSample(200, 200, 0); // too fast (<5ms since credited sample) -> ignored
  assert.equal(collector.collectedBits, 1);
  collector.lastSample = -1000;
  collector.addPointerSample(100, 100, 0); // duplicate position -> ignored
  assert.equal(collector.collectedBits, 1);
  collector.destroy();
});

test('hardenedRandomBytes mixes pool and CSPRNG', async () => {
  const pool = new Uint8Array(32).fill(7);
  const a = await S39.entropy.hardenedRandomBytes(64, pool);
  const b = await S39.entropy.hardenedRandomBytes(64, pool);
  assert.equal(a.length, 64);
  assert.equal(b.length, 64);
  assert.notDeepEqual(Array.from(a), Array.from(b), 'fresh CSPRNG salt must differ per call');
  assert.ok(a.some((v) => v !== 0));

  const pure = await S39.entropy.hardenedRandomBytes(16, null);
  assert.equal(pure.length, 16);
});

test('createHardenedRng serves synchronous draws and detects exhaustion', async () => {
  const pool = new Uint8Array(32).fill(3);
  const rng = await S39.entropy.createHardenedRng(pool, 64);
  const x = rng(32);
  const y = rng(32);
  assert.equal(x.length, 32);
  assert.notDeepEqual(Array.from(x), Array.from(y));
  assert.throws(() => rng(1), /exhausted/);
  rng.destroy();
});
