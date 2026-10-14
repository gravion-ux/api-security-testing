'use strict';

/**
 * Rate-limit detector.
 *
 * Given a target URL and a bearer token, the detector issues a burst
 * of requests and reports whether the server ever returned a 429
 * (or other throttle indicator) and what the rolling success rate was.
 *
 * The detector is read-only — every request uses GET — and runs in
 * parallel up to a configurable concurrency cap.
 *
 *   rateLimitProbe({
 *     url: 'http://127.0.0.1:4701/me/orders/1',
 *     token: 'tok-alice',
 *     total: 30,
 *     concurrency: 6,
 *   })
 *
 * Returns a structured report suitable for the JSON / Markdown writer.
 */

const { requestMethod } = require('./bola');

const THROTTLE_STATUSES = new Set([408, 425, 429, 503]);
const RETRY_AFTER_KEYS = ['retry-after'];

/**
 * @typedef {Object} RateLimitConfig
 * @property {string} url
 * @property {string} [token]
 * @property {number} [total=30]
 * @property {number} [concurrency=6]
 * @property {number} [timeoutMs=4000]
 *
 * @typedef {Object} RateLimitResult
 * @property {boolean} detected
 * @property {number} sent
 * @property {number} succeeded
 * @property {number} throttled
 * @property {Record<number,number>} statusCounts
 * @property {Array<{seq:number, status:number, retryAfter:number|null}>} samples
 * @property {string|null} summary
 */

async function rateLimitProbe(cfg) {
  const total = Math.max(1, Math.min(cfg.total || 30, 200));
  const concurrency = Math.max(1, Math.min(cfg.concurrency || 6, 50));
  const timeoutMs = cfg.timeoutMs || 4000;

  const samples = [];
  const statusCounts = {};
  let succeeded = 0;
  let throttled = 0;
  let next = 0;
  let detected = false;
  let firstThrottleAt = null;

  async function worker() {
    while (true) {
      const seq = next;
      next += 1;
      if (seq >= total) return;
      let res;
      try {
        res = await requestMethod(cfg.url, 'GET', cfg.token, timeoutMs);
      } catch (err) {
        res = { status: 0, body: { error: String(err) } };
      }
      const status = res.status || 0;
      statusCounts[status] = (statusCounts[status] || 0) + 1;
      const retryAfter = extractRetryAfter(res && res.body);
      const isThrottle = THROTTLE_STATUSES.has(status);
      if (isThrottle) {
        throttled += 1;
        if (firstThrottleAt === null) firstThrottleAt = seq;
        detected = true;
      } else if (status >= 200 && status < 300) {
        succeeded += 1;
      }
      samples.push({ seq, status, retryAfter });
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const summary = makeSummary({
    total, sent: samples.length, succeeded, throttled, statusCounts, firstThrottleAt,
  });

  return { detected, sent: samples.length, succeeded, throttled, statusCounts, samples, summary };
}

function extractRetryAfter(body) {
  if (!body || typeof body !== 'object') return null;
  for (const k of RETRY_AFTER_KEYS) {
    const v = body[k];
    if (typeof v === 'string' || typeof v === 'number') {
      const n = Number.parseInt(String(v), 10);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

function makeSummary({ total, sent, succeeded, throttled, statusCounts, firstThrottleAt }) {
  if (throttled === 0) {
    return `Sent ${sent} requests, none were throttled. The endpoint does not appear to apply per-user rate limits at this load.`;
  }
  const first = firstThrottleAt != null ? `first 429 at request #${firstThrottleAt + 1}` : null;
  return `Detected throttling: ${throttled}/${sent} requests returned a throttle status. ${first || ''}`.trim();
}

module.exports = { rateLimitProbe, THROTTLE_STATUSES };
