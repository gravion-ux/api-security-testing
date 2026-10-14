'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeServer } = require('../src/mock-server');

const SECURE_PORT = 4740;
const BOLA_PORT = 4741;

let secureServer;
let bolaServer;

test.before(async () => {
  secureServer = makeServer('secure', { port: SECURE_PORT });
  bolaServer = makeServer('bola', { port: BOLA_PORT });
  await new Promise((r) => setTimeout(r, 200));
});

test.after(async () => {
  for (const s of [secureServer, bolaServer]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});

function get(port, path, token) {
  return new Promise((resolve, reject) => {
    const http = require('node:http');
    const headers = { accept: 'application/json' };
    if (token) headers.authorization = `Bearer ${token}`;
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'GET', headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          let body; try { body = JSON.parse(raw); } catch { body = raw; }
          resolve({ status: res.statusCode, body });
        });
      }
    );
    req.on('error', reject);
    req.end();
  });
}

test('mock server: 401 without bearer', async () => {
  const r = await get(SECURE_PORT, '/me/orders/1');
  assert.equal(r.status, 401);
});

test('mock server: secure variant returns 403 on cross-owner read', async () => {
  const r = await get(SECURE_PORT, '/me/orders/2', 'tok-alice');
  assert.equal(r.status, 403);
});

test('mock server: secure variant returns 200 on owner read', async () => {
  const r = await get(SECURE_PORT, '/me/orders/1', 'tok-alice');
  assert.equal(r.status, 200);
  assert.equal(r.body.owner, 'alice');
});

test('mock server: BOLA variant returns 200 on cross-owner read (the bug)', async () => {
  const r = await get(BOLA_PORT, '/me/orders/2', 'tok-alice');
  assert.equal(r.status, 200);
  assert.equal(r.body.owner, 'bob');
});

test('mock server: 404 for unknown id', async () => {
  const r = await get(SECURE_PORT, '/me/orders/999', 'tok-alice');
  assert.equal(r.status, 404);
});

test('mock server: 404 for unknown path', async () => {
  const r = await get(SECURE_PORT, '/no-such-thing', 'tok-alice');
  assert.equal(r.status, 404);
});
