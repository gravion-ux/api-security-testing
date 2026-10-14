'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
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
  const r = run(['demo']);
  assert.equal(r.status, 0, `stderr: ${r.stderr}`);
  assert.match(r.stdout, /BOLA:/);
  assert.match(r.stdout, /Rate-limit:/);
});
