# Riftor handoff

Last updated: 2026-10-01

## Current objective

Build the standalone cybersecurity harness described in
[`docs/RESET_PLAN.md`](docs/RESET_PLAN.md), using Pi's SDK as an embedded agent
runtime. The user wants the harness itself to be downloadable and usable without
a separate Pi installation. The old RIFT philosophy is out of scope for now.

Application repository: <https://github.com/amanverasia/riftor>

Website repository: <https://github.com/amanverasia/riftor-website>

Website source/deployment has not been updated as part of this app work. The
configured product domain is `https://riftor.dev`.

## Repo checkpoint

- Branch: `main`
- App-code checkpoint: `6f2180c` — `Add SARIF 2.1.0 assessment reports`.
- `AGENTS.md` and this handoff document are added in a documentation-only
  commit after that application checkpoint; check current HEAD before resuming.
- Latest hosted CI run: `36858157762`, success.
- Working tree was clean before adding this handoff document.

## Implemented

- Standalone TypeScript CLI embeds `@earendil-works/pi-coding-agent`; no separate
  Pi CLI is required. Riftor uses its own agent directory and suppresses Pi
  shell/file/default tools and discovered extensions, skills, prompts, themes,
  and project context.
- Local multi-engagement authorization and scope management, expiry checks,
  exclusions, policy preview, and operator approval for every network action.
- Three low-impact adapters: HTTP `HEAD`, DNS A/AAAA, and TLS leaf-certificate
  metadata. HTTP/TLS pin to validated addresses. Private/special-use addresses
  require explicit IP/CIDR scope. Checks are bounded and do not follow HTTP
  redirects or download response bodies.
- Central action gateway holds a cross-process lease and rechecks policy before
  network work. Persistent workspace action budget allows up to 60 checks per
  rolling minute and applies a two-second cooldown per normalized
  target/activity pair across engagements and restarts. Failed/cancelled
  approved attempts consume reservations; imported workspaces do not carry the
  budget history.
- Local audit records and a SHA-256-linked evidence chain; validated findings
  with status, severity, confidence, remediation, and evidence references.
- Markdown, JSON, and SARIF 2.1.0 reports. SARIF omits resolved findings and
  marks accepted findings as suppressed; network targets and evidence details
  live in Riftor properties rather than file locations.
- Workspace JSON archives export/import engagements, evidence, and findings.
  Import validates into staging, refuses an existing workspace, and leaves all
  imported engagements inactive. Archives omit local audit logs, reports,
  provider credentials, and action-budget history. Their checksum is not an
  authenticity signature.
- CI uses Node 24-compatible GitHub Actions. Repo plan and threat model are in
  `docs/RESET_PLAN.md` and `docs/THREAT_MODEL.md`.

## Latest verification

At `6f2180c`, local checks passed:

- `npm test` — 45 tests passed.
- `npm audit --omit=dev` — zero vulnerabilities.
- `npm pack --dry-run` — succeeded.
- `git diff --check` — clean.
- Hosted CI run `36858157762` — success.

SARIF output was checked for core 2.1.0 fields and finding-state handling. It
has not been run through a full external schema validator.

## Known limitations and next steps

This is an active development build, not a finished or security-certified
product. The adapters are limited to HTTP headers, DNS A/AAAA, and TLS leaf
metadata; there is no arbitrary shell, port scanner, exploit runner,
vulnerability database, or credential testing. The local audit log is not
cryptographically chained. The action budget is best-effort local pacing, not a
tamper-resistant quota. There is no credential-entry wizard or multi-user
access control.

Suggested next work, in order:

1. Validate generated SARIF against the official SARIF 2.1.0 schema and test it
   with a consumer; keep target/evidence semantics clear for file-centric UIs.
2. Finish finding deduplication/review semantics without deleting original
   evidence.
3. Improve install/release documentation and cross-platform CI. Do not publish
   to npm or create a public release without explicit user instruction.
4. Add further assessment adapters only with typed target extraction, policy
   coverage, rate/impact controls, bounded network behavior, evidence, and
   approval tests.
5. Treat the website repo as a separate task; confirm its current contents and
   status before changing or deploying it.

## How to resume

Read this file, `AGENTS.md`, `docs/RESET_PLAN.md`, and
`docs/THREAT_MODEL.md`. Then check the user's latest message, `git status`, the
current branch/HEAD, and hosted CI before editing. Continue the user's newest
direction; do not assume this checkpoint means the project is complete. Keep
the user updated, test each security-sensitive change, commit and push when
requested, and report remaining limitations plainly.
