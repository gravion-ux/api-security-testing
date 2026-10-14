#!/usr/bin/env node
'use strict';

/**
 * Command-line entry point for api-security-testing.
 *
 *   api-sec demo                          # boots a BOLA-vulnerable mock and probes it
 *   api-sec bola --url <template>         # run a BOLA probe against an authorized target
 *   api-sec ratelimit --url <url>         # run a rate-limit probe against an authorized target
 *
 * Without arguments, prints --help.
 *
 * All probes are read-only and never mutate server state.
 */

const fs = require('node:fs');
const path = require('node:path');
const { bolaDetect } = require('./bola');
const { rateLimitProbe } = require('./rate-limit');
const { makeServer, renderReport } = require('./index');

const HELP = `api-sec — authorized API security testing harness

Usage:
  api-sec demo
  api-sec bola --url <url-template> [--id 1 2 3] [--token user:tok ...]
  api-sec ratelimit --url <url> [--token <bearer>] [--total N] [--concurrency N]
  api-sec --help

Notes:
  All probes are read-only. The demo command boots a local mock
  server on 127.0.0.1 and tears it down before exit.
`;

async function main(argv) {
  const args = argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  const cmd = args[0];
  if (cmd === 'demo') return runDemo();
  if (cmd === 'bola') return runBola(args.slice(1));
  if (cmd === 'ratelimit') return runRateLimit(args.slice(1));
  process.stderr.write(`Unknown command: ${cmd}\n`);
  return 2;
}

async function runDemo() {
  // Boot a BOLA-vulnerable mock on a free port
  const port = 4701;
  const server = makeServer('bola', { port });
  await new Promise((r) => setTimeout(r, 100));

  try {
    const bolaResult = await bolaDetect({
      urlTemplate: `http://127.0.0.1:${port}/me/orders/:id`,
      idRange: [1, 2, 3],
      sessions: { alice: 'tok-alice', bob: 'tok-bob', eve: 'tok-eve' },
      ownerHint: (body) => body && typeof body === 'object' ? body.owner : null,
    });

    // Boot a rate-limit-vulnerable mock on a separate port
    const port2 = 4711;
    const server2 = makeServer('rate-limit', { port: port2, burstLimit: 5, burstWindowMs: 2000 });
    await new Promise((r) => setTimeout(r, 100));

    const rateResult = await rateLimitProbe({
      url: `http://127.0.0.1:${port2}/me/orders/1`,
      token: 'tok-alice',
      total: 20,
      concurrency: 4,
    });

    server2.close();
    server.close();

    const report = renderReport(bolaResult, rateResult, { demo: true });
    const out = path.resolve('api-sec-report.json');
    fs.writeFileSync(out, JSON.stringify(report, null, 2));
    process.stdout.write(`Wrote ${out}\n`);
    process.stdout.write(`BOLA: ${report.bola.leakCount} leaks across ${report.bola.sampleCount} samples (detected=${report.bola.detected})\n`);
    process.stdout.write(`Rate-limit: ${report.rateLimit.throttled} throttled of ${report.rateLimit.sent} requests (detected=${report.rateLimit.detected})\n`);
    return 0;
  } finally {
    try { server.close(); } catch {}
  }
}

async function runBola(args) {
  const opts = parseBolaArgs(args);
  if (!opts.ok) { process.stderr.write(opts.error + '\n'); return 2; }

  const result = await bolaDetect({
    urlTemplate: opts.url,
    idRange: opts.ids,
    sessions: opts.sessions,
    ownerHint: (body) => body && typeof body === 'object' ? body.owner : null,
  });
  process.stdout.write(JSON.stringify(result, null, 2));
  return 0;
}

async function runRateLimit(args) {
  const opts = parseRateArgs(args);
  if (!opts.ok) { process.stderr.write(opts.error + '\n'); return 2; }

  const result = await rateLimitProbe({
    url: opts.url,
    token: opts.token,
    total: opts.total,
    concurrency: opts.concurrency,
  });
  process.stdout.write(JSON.stringify(result, null, 2));
  return 0;
}

function parseBolaArgs(args) {
  const out = { ok: true, ids: [1, 2, 3], sessions: {} };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--url') { out.url = args[++i]; continue; }
    if (a === '--id') {
      out.ids = [];
      while (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        out.ids.push(Number.parseInt(args[++i], 10));
      }
      continue;
    }
    if (a === '--token') {
      const raw = args[++i] || '';
      const idx = raw.indexOf(':');
      if (idx < 0) return { ok: false, error: '--token expects user:token' };
      out.sessions[raw.slice(0, idx)] = raw.slice(idx + 1);
      continue;
    }
    return { ok: false, error: `unknown flag: ${a}` };
  }
  if (!out.url) return { ok: false, error: '--url is required' };
  return out;
}

function parseRateArgs(args) {
  const out = { ok: true, total: 30, concurrency: 6 };
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === '--url') { out.url = args[++i]; continue; }
    if (a === '--token') { out.token = args[++i]; continue; }
    if (a === '--total') { out.total = Number.parseInt(args[++i], 10); continue; }
    if (a === '--concurrency') { out.concurrency = Number.parseInt(args[++i], 10); continue; }
    return { ok: false, error: `unknown flag: ${a}` };
  }
  if (!out.url) return { ok: false, error: '--url is required' };
  return out;
}

main(process.argv)
  .then((code) => process.exit(typeof code === 'number' ? code : 0))
  .catch((err) => { process.stderr.write(`fatal: ${err && err.message ? err.message : err}\n`); process.exit(1); });
