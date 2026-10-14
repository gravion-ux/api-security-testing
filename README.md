# API Security Testing

An **authorized-only** API security testing harness. Two focused
detectors — a BOLA / cross-tenant leak probe and a rate-limit probe —
plus a small local mock server that simulates a vulnerable API so the
harness can be exercised end-to-end without ever leaving the loopback
address.

> **Scope statement.** The harness only ever makes **read-only GET
> requests** to URLs the operator explicitly names. It refuses to
> fuzz, mutate state, or send payloads. It is intended for systems
> you own or have written authorization to test, and for the bundled
> mock server (which binds to `127.0.0.1`).

## What's here

| path | purpose |
| --- | --- |
| `src/bola.js`         | BOLA / cross-owner read detector |
| `src/rate-limit.js`   | Burst-probe rate-limit detector |
| `src/mock-server.js`  | Local mock API (`secure`, `bola`, `rate-limit` modes) |
| `src/index.js`        | Public API surface + report renderer |
| `src/cli.js`          | `api-sec` command-line entry point |
| `test/*.test.js`      | Automated coverage for every module |
| `examples/`           | Sample JSON reports |

## Quick start

You need Node.js 18+ (no external dependencies).

```bash
# 1. run the demo end-to-end (boots local mock servers on 127.0.0.1)
npm run demo
# → writes ./api-sec-report.json
# → prints:
#     BOLA: 6 leaks across 9 samples (detected=true)
#     Rate-limit: 13 throttled of 20 requests (detected=true)

# 2. run a BOLA probe against an authorized target
node src/cli.js bola --url http://127.0.0.1:4701/me/orders/:id \
                    --id 1 2 3 \
                    --token alice:tok-alice --token bob:tok-bob

# 3. run a rate-limit probe
node src/cli.js ratelimit --url http://127.0.0.1:4711/me/orders/1 \
                          --token tok-alice --total 30 --concurrency 6

# 4. run the test suite
npm test
```

## How the BOLA probe works

`bolaDetect({ urlTemplate, idRange, sessions, ownerHint })`

1. For every (user, id) pair in the cross-product of `sessions` and
   `idRange`, the probe issues a single `GET` against
   `urlTemplate` with the user's bearer token.
2. Each response is scored: if the response was 2xx and the
   `ownerHint(body)` returns a different user name than the requester,
   the probe records a probable **object-level authorization leak**.
3. The detector is **read-only** — every request is a GET — and
   **stateless** — it never persists or replays the responses.

## How the rate-limit probe works

`rateLimitProbe({ url, token, total, concurrency })`

1. Issues `total` GETs at the same URL, up to `concurrency` in flight.
2. Records the response status of every request.
3. Any status in `{408, 425, 429, 503}` counts as throttling.
4. The summary returns the success / throttle counts and the index of
   the first throttled request — useful for tuning limit policies.

## Sample report

```json
{
  "tool": "api-security-testing",
  "generatedAt": "2026-10-14T...",
  "bola": {
    "detected": true,
    "leakCount": 6,
    "sampleCount": 9,
    "byUser": {
      "alice": { "sent": 3, "leaked": 2 },
      "bob":   { "sent": 3, "leaked": 2 },
      "eve":   { "sent": 3, "leaked": 2 }
    }
  },
  "rateLimit": {
    "detected": true,
    "sent": 20,
    "succeeded": 7,
    "throttled": 13,
    "statusCounts": { "200": 7, "429": 13 },
    "summary": "Detected throttling: 13/20 requests returned a throttle status. first 429 at request #6"
  }
}
```

## What this is **not**

- It is not a fuzzer. It does not generate or replay payloads.
- It is not a scanner. It will not enumerate paths or try default
  credentials.
- It is not a substitute for a manual, scope-driven assessment.
  Especially for object-level authorization, the *business* ownership
  rule must be encoded in `ownerHint`; the detector will not invent it.

## Security & ethics

- The mock server binds to `127.0.0.1` only. Do not change the bind
  address to `0.0.0.0`.
- The probes are stateless. They will not leave fingerprints in
  application logs beyond the obvious HTTP entries.
- The mock server is a teaching aid, not a target. Do not run
  unrelated probes against it.

## License

MIT — see [`LICENSE`](./LICENSE).
