'use strict';

/**
 * Public API surface for the API security testing harness.
 *
 * Exposes:
 *   - bolaDetect(cfg)         — probe for object-level authorization leaks
 *   - rateLimitProbe(cfg)     — burst a URL and detect throttling
 *   - makeServer(mode, opts)  — build a local mock server (used by tests and demo)
 *   - renderReport(results)   — produce a JSON-serializable summary
 *
 * Tests import these directly; the CLI in src/cli.js is a thin wrapper.
 */

const { bolaDetect } = require('./bola');
const { rateLimitProbe } = require('./rate-limit');
const { makeServer } = require('./mock-server');

function summarizeBola(result) {
  if (!result || !Array.isArray(result.samples)) {
    return { detected: false, leakCount: 0, sampleCount: 0, byUser: {} };
  }
  const leaks = result.samples.filter((s) => s.leak);
  const byUser = {};
  for (const s of result.samples) {
    if (!byUser[s.user]) byUser[s.user] = { sent: 0, leaked: 0 };
    byUser[s.user].sent += 1;
    if (s.leak) byUser[s.user].leaked += 1;
  }
  return {
    detected: result.detected,
    leakCount: leaks.length,
    sampleCount: result.samples.length,
    byUser,
  };
}

function renderReport(bolaResult, rateLimitResult, meta = {}) {
  return {
    tool: 'api-security-testing',
    generatedAt: new Date().toISOString(),
    meta,
    bola: bolaResult ? summarizeBola(bolaResult) : null,
    rateLimit: rateLimitResult ? {
      detected: rateLimitResult.detected,
      sent: rateLimitResult.sent,
      succeeded: rateLimitResult.succeeded,
      throttled: rateLimitResult.throttled,
      statusCounts: rateLimitResult.statusCounts,
      summary: rateLimitResult.summary,
    } : null,
  };
}

module.exports = {
  bolaDetect,
  rateLimitProbe,
  makeServer,
  renderReport,
  summarizeBola,
};
