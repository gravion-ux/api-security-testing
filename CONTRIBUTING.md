# Contributing to api-security-testing

Thanks for helping! `api-security-testing` is an **authorized-only** API
security testing harness. It ships two focused test families — BOLA/IDOR
(object-level authorization) and rate-limit behaviour — that run against
the bundled local test server or a target you are explicitly authorized
to test.

## Ground rules

- **Authorized targets only — hard rule.** Never run the harness against
  an API you do not own or have written permission to test. The bundled
  server exists so every check can be developed and verified locally.
- **Zero runtime dependencies.** Node.js standard library only.
- **Checks demonstrate, they don't damage.** Tests must be
  non-destructive: no data deletion, no load generation beyond the
  rate-limit probes' small, bounded request counts.

## Development setup

Requires Node.js 18 or newer. There is nothing to install.

```bash
git clone https://github.com/gravion-ux/api-security-testing.git
cd api-security-testing
npm test
```

## Running the tests

```bash
npm test        # bola, rate-limit, cli and server suites (node --test)
npm run demo    # end-to-end demo against the bundled server
```

## Adding a check

1. Implement the check under `src/`, in the style of the existing
   BOLA / rate-limit modules: a function that takes a target + options
   and returns structured findings (id, severity, detail, remediation).
2. Add tests in `test/` that run against the bundled server — a
   vulnerable configuration that must be flagged and a correctly
   configured one that must pass clean.
3. List the new check in the README.

## Pull request workflow

1. Fork and branch from `main`: `feat/<short-name>`, `fix/<short-name>`
   or `check/<check-id>`.
2. Run `npm test` and `npm run demo` locally — both must pass.
3. Open the PR against `main` with: what changed, why, and how the
   bundled-server tests prove it.
4. CI must be green (Node 18, 20 and 22).
5. One logical change per PR.
