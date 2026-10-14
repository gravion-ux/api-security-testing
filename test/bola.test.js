'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeServer } = require('../src/mock-server');
const { bolaDetect } = require('../src/bola');

const SECURE_PORT = 4720;
const BOLA_PORT = 4721;

let secureServer;
let bolaServer;

test.before(async () => {
  secureServer = makeServer('secure', { port: SECURE_PORT });
  bolaServer = makeServer('bola', { port: BOLA_PORT });
  // give the listeners a tick to bind
  await new Promise((r) => setTimeout(r, 200));
});

test.after(async () => {
  for (const s of [secureServer, bolaServer]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});

const SESSIONS = { alice: 'tok-alice', bob: 'tok-bob', eve: 'tok-eve' };

test('BOLA: detects cross-owner reads on a vulnerable server', async () => {
  const r = await bolaDetect({
    urlTemplate: `http://127.0.0.1:${BOLA_PORT}/me/orders/:id`,
    idRange: [1, 2, 3],
    sessions: SESSIONS,
    ownerHint: (body) => body && body.owner,
  });
  assert.equal(r.detected, true, 'BOLA must be detected on the vulnerable variant');
  // alice reading order 2 (bob's) is a leak; bob reading order 1 (alice's) is a leak
  const leaks = r.samples.filter((s) => s.leak);
  assert.ok(leaks.length >= 2, `expected at least 2 leaks, got ${leaks.length}`);
});

test('BOLA: does not flag the secure server', async () => {
  const r = await bolaDetect({
    urlTemplate: `http://127.0.0.1:${SECURE_PORT}/me/orders/:id`,
    idRange: [1, 2, 3],
    sessions: SESSIONS,
    ownerHint: (body) => body && body.owner,
  });
  // secure server returns 403 on cross-owner requests → no leak samples
  assert.equal(r.detected, false, 'no BOLA on the secure variant');
  // and every sample should be either a successful self-read or a 403
  for (const s of r.samples) {
    if (s.status === 200) {
      assert.equal(s.body.owner, s.user, 'successful reads must be the owner');
    } else {
      assert.equal(s.status, 403, 'cross-owner reads return 403');
    }
  }
});

test('BOLA: cross-tenant profile reads are detected on the vulnerable server', async () => {
  const r = await bolaDetect({
    urlTemplate: `http://127.0.0.1:${BOLA_PORT}/users/:id/profile`,
    idRange: ['alice', 'bob', 'eve'],
    sessions: SESSIONS,
    ownerHint: (body) => body && body.tenant,
  });
  // eve is in tenant 'globex'; the others are in 'acme'. On the
  // vulnerable variant eve can read alice/bob profiles → tenant mismatch.
  // (ownerHint returns tenant; leak is when tenant-derived owner != user
  //  but the status was 2xx. We expect cross-tenant leaks.)
  const leaks = r.samples.filter((s) => s.leak);
  assert.ok(leaks.length > 0, 'cross-tenant reads should be flagged');
});

test('BOLA: cross-tenant profile reads are blocked on the secure server', async () => {
  // Cross-tenant isolation is a *tenant* check, not a per-user ownership
  // check, so we don't use the ownerHint here — we directly assert that
  // every request whose target tenant differs from the requester's tenant
  // returned 403.
  const requesterTenant = { alice: 'acme', bob: 'acme', eve: 'globex' };
  const targetTenant = { alice: 'acme', bob: 'acme', eve: 'globex' };

  const r = await bolaDetect({
    urlTemplate: `http://127.0.0.1:${SECURE_PORT}/users/:id/profile`,
    idRange: ['alice', 'bob', 'eve'],
    sessions: SESSIONS,
    ownerHint: (body) => body && body.tenant,
  });

  for (const s of r.samples) {
    const isCrossTenant = requesterTenant[s.user] !== targetTenant[s.id];
    if (isCrossTenant) {
      assert.equal(s.status, 403, `${s.user} → /users/${s.id}/profile must be 403 (cross-tenant)`);
    } else {
      assert.equal(s.status, 200, `${s.user} → /users/${s.id}/profile must be 200 (same-tenant)`);
    }
  }
});
