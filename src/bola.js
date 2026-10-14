'use strict';

/**
 * BOLA (Broken Object Level Authorization) detector.
 *
 * Given a URL template with an embedded `:{id}` segment and a set of
 * session tokens, the detector issues a request from each session,
 * collects the response, and reports any cases where a session can
 * observe a record owned by another session.
 *
 *   bolaDetect({
 *     urlTemplate: 'http://127.0.0.1:4701/me/orders/:id',
 *     idRange: [1, 2, 3],
 *     sessions: { alice: 'tok-alice', bob: 'tok-bob', eve: 'tok-eve' },
 *     ownerHint: (body, url) => body.owner  // optional
 *   })
 *
 * Returns a structured report describing the observed behavior. The
 * detector never mutates server state — every request is a GET.
 */

const http = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

/**
 * @typedef {Object} BolaConfig
 * @property {string} urlTemplate   URL with `:{id}` token, e.g. /orders/:id
 * @property {number[]} idRange     List of integer ids to probe
 * @property {Record<string,string>} sessions  Mapping of user-name → bearer token
 * @property {number} [timeoutMs]
 * @property {(body: any, url: string) => string|null} [ownerHint]
 *    Optional helper that extracts an owner identifier from a response body.
 *    When the hint returns a string and it doesn't match the requesting
 *    user, the request is reported as a probable BOLA leak.
 *
 * @typedef {Object} BolaResult
 * @property {boolean} detected        True if any probable BOLA leak was found
 * @property {Array<{user:string, id:number, status:number, body:any, owner:string|null, leak:boolean}>} samples
 */

function substitute(template, id) {
  return template.replace(/:id\b/g, String(id));
}

function requestMethod(urlText, method, token, timeoutMs) {
  return new Promise((resolve, reject) => {
    let url;
    try { url = new URL(urlText); }
    catch (e) { return reject(new Error(`bad URL: ${urlText}`)); }
    const transport = url.protocol === 'https:' ? https : http;
    const headers = { accept: 'application/json' };
    if (token) headers.authorization = `Bearer ${token}`;
    const req = transport.request(
      { method, hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: `${url.pathname}${url.search}`, headers, timeout: timeoutMs },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          let body = null;
          try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
          resolve({ status: res.statusCode, body });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (err) => reject(err));
    req.end();
  });
}

/**
 * Run the BOLA probe.
 *
 * @param {BolaConfig} cfg
 * @returns {Promise<BolaResult>}
 */
async function bolaDetect(cfg) {
  const timeoutMs = cfg.timeoutMs || 5000;
  const samples = [];
  let detected = false;

  for (const [user, token] of Object.entries(cfg.sessions)) {
    for (const id of cfg.idRange) {
      const url = substitute(cfg.urlTemplate, id);
      let res;
      try {
        res = await requestMethod(url, 'GET', token, timeoutMs);
      } catch (err) {
        samples.push({ user, id, status: 0, body: { error: String(err) }, owner: null, leak: false, error: String(err) });
        continue;
      }
      const owner = cfg.ownerHint ? cfg.ownerHint(res.body, url) : null;
      const leak = !!owner && owner !== user && res.status >= 200 && res.status < 300;
      if (leak) detected = true;
      samples.push({ user, id, status: res.status, body: res.body, owner, leak });
    }
  }

  return { detected, samples };
}

module.exports = { bolaDetect, requestMethod, substitute };
