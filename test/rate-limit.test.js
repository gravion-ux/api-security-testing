'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeServer } = require('../src/mock-server');
const { rateLimitProbe, THROTTLE_STATUSES } = require('../src/rate-limit');

const LIMITED_PORT = 4730;
const UNLIMITED_PORT = 4731;

let limitedServer;
let unlimitedServer;

test.before(async () => {
  // Tight burst: 5 requests per 1s window
  limitedServer = makeServer('rate-limit', { port: LIMITED_PORT, burstLimit: 5, burstWindowMs: 1000 });
  unlimitedServer = makeServer('secure', { port: UNLIMITED_PORT });
  await new Promise((r) => setTimeout(r, 200));
});

test.after(async () => {
  for (const s of [limitedServer, unlimitedServer]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});

test('rate-limit: detects throttling on a rate-limited server', async () => {
  const r = await rateLimitProbe({
    url: `http://127.0.0.1:${LIMITED_PORT}/me/orders/1`,
    token: 'tok-alice',
    total: 20,
    concurrency: 4,
  });
  assert.equal(r.detected, true);
  assert.ok(r.throttled > 0, 'at least one request should be throttled');
  // every recorded status should be one of 200, 429 (no surprise codes)
  for (const s of r.samples) {
    assert.ok(s.status === 200 || s.status === 429, `unexpected status ${s.status}`);
  }
});

test('rate-limit: does not flag a server that has no throttle', async () => {
  const r = await rateLimitProbe({
    url: `http://127.0.0.1:${UNLIMITED_PORT}/me/orders/1`,
    token: 'tok-alice',
    total: 10,
    concurrency: 3,
  });
  assert.equal(r.detected, false);
  assert.equal(r.throttled, 0);
  // all should be 200
  for (const s of r.samples) {
    assert.equal(s.status, 200);
  }
});

test('THROTTLE_STATUSES: includes 429 and 503', () => {
  assert.ok(THROTTLE_STATUSES.has(429));
  assert.ok(THROTTLE_STATUSES.has(503));
  assert.equal(THROTTLE_STATUSES.has(200), false);
});
