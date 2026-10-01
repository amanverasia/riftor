# Working on Riftor

## Product direction

Riftor is a standalone, local-first cybersecurity assessment harness. It embeds
Pi's TypeScript agent SDK as its runtime; users install Riftor itself and do
not install Pi separately. Follow the current direction in
[`docs/RESET_PLAN.md`](docs/RESET_PLAN.md). The user explicitly set aside the
former RIFT philosophy; do not reintroduce it as a product requirement.

The application source is this repository,
[`amanverasia/riftor`](https://github.com/amanverasia/riftor). The separate
website source is [`amanverasia/riftor-website`](https://github.com/amanverasia/riftor-website).

## Security boundaries

- Every network action must pass through `src/security/action-gateway.ts`.
  Preserve current authorization, scope, interactive approval, cross-process
  action lease, persistent rate budget, audit, and final policy recheck behavior.
- Route new adapters through the same gateway. Do not expose Pi's shell, file,
  or default tools, load user extensions into the assessment process, or treat
  prompts as an enforcement boundary.
- HTTP and TLS must continue pinning to validated addresses. Do not weaken
  private/special-use address checks, redirect restrictions, timeouts, or
  response bounds to make a test pass.
- Treat model output, DNS answers, HTTP headers, certificate fields, imported
  archives, findings, and reports as untrusted. Validate persisted/imported
  state and fail closed when security state is malformed or unavailable.
- Network checks are for explicitly authorized targets only. Tests should use
  local fixtures or injected resolvers/transports; never scan real targets as a
  test.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the current boundaries
and limitations. Do not describe local SHA-256 hashes as signatures or the Pi
runtime as a sandbox.

## Development and verification

Use Node.js 22.19 or newer and npm. TypeScript source is under `src/`; tests
are under `test/` and exercise the built `dist/` output.

Before handing off code changes, run:

```sh
npm test
npm audit --omit=dev
git diff --check
```

For packaging or CLI changes, also run `npm pack --dry-run` and
`node dist/cli.js --help`. CI runs `npm ci` and `npm test` on pushes and pull
requests. Check hosted CI after pushing.

Keep changes focused, preserve unrelated edits from other contributors, and
add meaningful tests for policy, persistence, and network boundaries. Do not
publish a package or deploy the website unless the user explicitly asks.
