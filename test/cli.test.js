'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf-8', timeout: 20_000 });
}

test('CLI: --help prints usage', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /api-sec/);
  assert.match(r.stdout, /bola/);
  assert.match(r.stdout, /ratelimit/);
});

test('CLI: unknown command exits 2', () => {
  const r = run(['banana']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Unknown command/);
});

test('CLI: bola without --url exits 2', () => {
  const r = run(['bola']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--url is required/);
});

test('CLI: ratelimit without --url exits 2', () => {
  const r = run(['ratelimit']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--url is required/);
});

test('CLI: demo runs end-to-end and exits 0', () => {
  // The report is written to a temporary file, not into the repository, so a
  // test run never leaves the working tree dirty.
  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'api-sec-test-')), 'report.json');
  const r = run(['demo', '--out', tmp]);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /BOLA:/);
  assert.match(r.stdout, /Rate-limit:/);
  assert.ok(fs.existsSync(tmp), 'the demo report must be written where --out said');

  const report = JSON.parse(fs.readFileSync(tmp, 'utf-8'));
  assert.equal(report.meta.demo, true);
  assert.equal(report.bola.detected, true);
  assert.equal(report.rateLimit.detected, true);
});

test('CLI: demo rejects an unknown flag with exit 2', () => {
  const r = run(['demo', '--banana']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown flag/);
});
