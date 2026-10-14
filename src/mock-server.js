'use strict';

/**
 * Local mock API server used by the BOLA / rate-limit detector.
 *
 * The server models a tiny resource API:
 *
 *   GET  /me/orders/:id          — owner-only access (vulnerable variant leaks)
 *   GET  /users/:id/profile      — only same-tenant users (vulnerable variant leaks)
 *   POST /orders                 — create an order, charges cart
 *
 * The vulnerable and secure variants are mutually exclusive so the test
 * suite can prove each behavior. Mode is chosen by `mode=secure|bola`.
 *
 * NEVER expose this server on a routable interface. The server binds to
 * 127.0.0.1 by default and ignores requests outside its small whitelist.
 */

const http = require('node:http');

function makeServer(mode = 'secure', opts = {}) {
  const PORT = Number.parseInt(opts.port || process.env.PORT || '4701', 10);
  const HOST = opts.host || '127.0.0.1';

  const sessions = { 'tok-alice': 'alice', 'tok-bob': 'bob', 'tok-eve': 'eve' };

  const orders = {
    '1': { id: 1, owner: 'alice', amount: 12.5, items: ['mug'] },
    '2': { id: 2, owner: 'bob',   amount: 99.0, items: ['hoodie'] },
    '3': { id: 3, owner: 'eve',   amount: 50.0, items: ['book'] },
  };

  const users = {
    alice: { id: 1, name: 'alice', tenant: 'acme',  email: 'alice@acme.test' },
    bob:   { id: 2, name: 'bob',   tenant: 'acme',  email: 'bob@acme.test'   },
    eve:   { id: 3, name: 'eve',   tenant: 'globex',email: 'eve@globex.test' },
  };

  // simple in-memory token bucket for the rate-limited variant
  const buckets = new Map();
  const burstLimit = opts.burstLimit || 5;
  const burstWindowMs = opts.burstWindowMs || 1000;

  function getBearer(req) {
    const h = req.headers.authorization || '';
    const m = /^Bearer\s+([A-Za-z0-9_\-]+)/.exec(h);
    return m ? m[1] : null;
  }

  function authenticatedUser(req) {
    const tok = getBearer(req);
    return tok && sessions[tok] ? sessions[tok] : null;
  }

  function isRateLimited(user) {
    if (mode !== 'rate-limit') return false;
    const now = Date.now();
    const bucket = buckets.get(user) || [];
    const recent = bucket.filter((t) => now - t < burstWindowMs);
    recent.push(now);
    buckets.set(user, recent);
    return recent.length > burstLimit;
  }

  function parseUrl(path) {
    const u = new URL(path, 'http://127.0.0.1');
    return u;
  }

  return http.createServer((req, res) => {
    // 30-byte cap on JSON bodies; this is a mock
    const chunks = [];
    let aborted = false;
    req.on('data', (c) => {
      if (aborted) return;
      chunks.push(c);
      if (chunks.reduce((n, b) => n + b.length, 0) > 30 * 1024) {
        aborted = true;
        req.destroy();
      }
    });
    req.on('end', () => handle(req, res));
    req.on('error', () => {});

    function handle(req, res) {
      const rawBody = Buffer.concat(chunks).toString('utf-8');
      let body = {};
      try { body = rawBody ? JSON.parse(rawBody) : {}; } catch { body = {}; }

      const url = parseUrl(req.url);
      const user = authenticatedUser(req);
      res.setHeader('content-type', 'application/json');

      if (!user) {
        res.writeHead(401);
        res.end(JSON.stringify({ error: 'unauthenticated' }));
        return;
      }
      if (isRateLimited(user)) {
        res.writeHead(429, { 'retry-after': '1' });
        res.end(JSON.stringify({ error: 'rate_limited' }));
        return;
      }

      const orderMatch = /^\/me\/orders\/(\d+)\/?$/.exec(url.pathname);
      if (orderMatch && req.method === 'GET') {
        const id = orderMatch[1];
        const order = orders[id];
        if (!order) {
          res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return;
        }
        if (mode === 'secure') {
          if (order.owner !== user) {
            res.writeHead(403); res.end(JSON.stringify({ error: 'forbidden' })); return;
          }
        }
        // vulnerable mode: leaks regardless of owner
        res.writeHead(200);
        res.end(JSON.stringify(order));
        return;
      }

      const profileMatch = /^\/users\/(\w+)\/profile\/?$/.exec(url.pathname);
      if (profileMatch && req.method === 'GET') {
        const name = profileMatch[1];
        const target = users[name];
        if (!target) {
          res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return;
        }
        if (mode === 'secure') {
          const me = users[user];
          if (!me || me.tenant !== target.tenant) {
            res.writeHead(403); res.end(JSON.stringify({ error: 'forbidden' })); return;
          }
        }
        // vulnerable mode: leaks across tenants
        res.writeHead(200);
        res.end(JSON.stringify(target));
        return;
      }

      if (url.pathname === '/orders' && req.method === 'POST') {
        res.writeHead(201);
        res.end(JSON.stringify({ status: 'created', by: user, body }));
        return;
      }

      res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' }));
    }
  }).listen(PORT, HOST, () => {
    console.log(`[mock-server mode=${mode}] http://${HOST}:${PORT}/ (tok-alice, tok-bob, tok-eve)`);
  });
}

module.exports = { makeServer };
