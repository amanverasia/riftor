# Riftor launch handoff

**Status snapshot:** 2026-10-05. Verify all remote and live state again before
continuing; GitHub and hosting configuration can change independently of this
checkout.

## Summary

Riftor's application source is public on GitHub and the current `main` branch
passes CI. The website source has been updated for the Pi-powered rebuild and
is already on the website repository's `main`, but that version is not live at
`riftor.dev`. The website security remediation and CI workflow are now merged
to its `main`. The application alpha preparation is also merged to `main`.
Riftor has no v5 release or published npm package yet.

Keep the application and website in their separate repositories. There is no
cross-repository merge to perform. A version- and context-checked local
security fix for the website dependency is in place until upstream behavior is
verified as fixed. The live domain still needs hosting verification and an
explicit deployment request. The application is at `5.0.0-alpha.0`; choosing a
distribution target and publishing it remain future work. Do not deploy or
publish until the user explicitly asks for that external action.

## Product and repository context

- Product direction: [`RESET_PLAN.md`](RESET_PLAN.md). Riftor is a standalone,
  local-first cybersecurity assessment harness embedding Pi's TypeScript SDK.
  Do not restore the former RIFT philosophy as a product requirement.
- Application: <https://github.com/amanverasia/riftor>
- Website source: <https://github.com/amanverasia/riftor-website>
- Public domain: <https://riftor.dev>
- Keep the two repositories separate; link between them rather than merging
  their Git histories.

The currently implemented network activities are HTTP `HEAD` header
inspection, DNS A/AAAA lookup, and TLS leaf-certificate inspection. Each uses
Riftor's authorization and scope checks, interactive approval, policy gateway,
audit record, and evidence handling. Broader adapters, MCP/skills integration,
and additional recovery/release work remain planned. Describe an initial
release as a limited alpha unless the product scope is expanded and reviewed.

## Application repository: verified state

- On 2026-10-05, the working tree was clean at `main`, commit `742b037`
  (`Clarify unconfigured model status`), synchronized with `origin/main`.
- Hosted main CI passed for that commit:
  <https://github.com/amanverasia/riftor/actions/runs/36874428682>
- Local verification on Node `v26.8.2` / npm `11.19.1`:
  - `npm test`: 50 passed on the final standalone run. An earlier run had one
    `http-transport.test.js` file-level failure that did not reproduce. Avoid
    running tests concurrently with `npm pack`: packing invokes `prepare`,
    which cleans and rebuilds `dist/`, while tests import that output.
  - `npm audit --omit=dev`: 0 vulnerabilities.
  - `git diff --check`: passed.
  - `npm pack --dry-run`: passed; it included the built CLI, README, and
    license. It did not publish a tarball.
  - `node dist/cli.js --help`: passed.
- At the verified main baseline, `package.json` was version `5.0.0-dev.0`. No
  v5 tag or GitHub release exists, the public npm lookup for `riftor` returned
  404, and there is no application release/publish workflow.
- Local main is clean; hosted open branches are Dependabot branches for PRs
  #5, #6, and #7. These are optional dependency updates, not changes already
  merged into main:
  - [PR #5: TypeBox update](https://github.com/amanverasia/riftor/pull/5) — CI
    failed in the persistent action-budget assertion at
    `test/action-gateway.test.js:137` (`true !== false`). The patch only changes
    TypeBox and the lockfile; do not merge until the failure is understood and
    CI passes.
  - [PR #6: Pi coding-agent 1.0.0](https://github.com/amanverasia/riftor/pull/6)
    — hosted CI passes, but the PR lockfile records nested
    `brace-expansion@5.0.9` under Pi. A production-only audit of a disposable
    checkout reports a high-severity vulnerability there. The `5.0.12` override
    remains in `package.json` but is not reflected in the nested lock entry.
    Ensure the nested resolution is patched and complete the runtime
    security-boundary review before considering this major update.
  - [PR #7: Node type definitions 26.6.4](https://github.com/amanverasia/riftor/pull/7)
    — hosted CI passes, but raises `@types/node` from 22 to 26 while Riftor
    still supports Node `>=22.19.0` and CI runs Node 22. Align the declarations
    with the supported runtime or establish that the type-only major update is
    intentional before merge.

### Remote recheck (2026-10-05)

- GitHub `main` is still `742b037`; the three Dependabot PRs above remain open.
  PRs #6 and #7 have passing hosted checks; PR #5's hosted test run still
  fails as described above.
- The latest application main CI run is green on `742b037`.
- A disposable checkout of PR #6 failed `npm audit --omit=dev`: nested
  `brace-expansion@5.0.9` is affected by
  [GHSA-6j4f-fj2g-mc7p](https://github.com/advisories/GHSA-6j4f-fj2g-mc7p),
  which lists 5.0.10 as the patched version. The current
  [GHSA-q2hr-2g5m-vwhr advisory](https://github.com/advisories/GHSA-q2hr-2g5m-vwhr)
  requires `brace-expansion` 5.0.12 or newer. Ensure the nested lock
  resolution reaches that version when reviewing any Pi 1.0.0 update; the
  root override alone did not change the PR lock entry.
- `gh release list` returned no releases, and `npm view riftor version`
  returned 404. No v5 release or npm package has been published.

Do not merge or delete these PR branches blindly. Review the failed test and
the major Pi runtime change; current `main` does not depend on them.

### Local alpha preparation (2026-10-05)

- The uncommitted working tree now prepares version `5.0.0-alpha.0` in
  `package.json` and `package-lock.json`, adds `CHANGELOG.md`, includes that
  changelog in the package tarball, and labels the README's scope as an early
  alpha. No tag, GitHub release, or package publication was created.
- Verification on Node `v26.8.2` / npm `11.19.1`: `npm test` passed (50/50),
  `npm audit --omit=dev` reported zero vulnerabilities, `git diff --check`
  passed, `npm pack --dry-run` included the changelog and built CLI, and
  `node dist/cli.js --help` passed.
- The local action-gateway persistence test now uses long test-only cooldown
  and window limits. It checks stored budget behavior, not expiration, so a
  50 ms threshold could expire during ordinary CI/filesystem delays. This
  addresses the observed PR #5 failure mode locally; the PR branch itself was
  not changed or rerun.
- A local tarball was installed into `/tmp/riftor-alpha-install-final`; the
  installed CLI's `--help` passed. The sandbox blocked an `esbuild` install
  script with `EPERM`, so the successful clean install used `--ignore-scripts`.
  `dist/` is included in the package. The tarball is in
  `/tmp/riftor-alpha-artifacts-final/riftor-5.0.0-alpha.0.tgz` and was not
  published.

## Website repository and live domain: verified state

- Website `main` contains commit `fe5ff41` (`Refresh Riftor site for the
  Pi-powered rebuild`). There are no open website PRs. The source update is
  already on that repository's main branch.
- A temporary checkout of that commit built successfully with `npm run build`.
  No website working copy was retained in the application repository.
- `riftor-website` has a `Deploy to GitHub Pages` workflow that runs only on
  `workflow_dispatch`. At the time of inspection, the repository reported
  GitHub Pages disabled and no deployment runs.
- The live `riftor.dev` still served the old Python/RIFT v3.1 copy, including
  `pip install riftor` and a link to `Estudely/riftor`. Its HTTP
  `Last-Modified` was 2026-07-09. Do not assume the old live content's hosting
  or DNS target; verify the intended host and domain ownership/routing before
  a cutover.
- `npm ci` and `npm run build` succeeded in the temporary checkout, but npm's
  audit reported one high-severity transitive finding:
  `http-cache-semantics@4.2.0`, pulled in by `astro@7.3.5`. npm initially
  reported a fix; follow-up source review found its proposed 4.3.0 update does
  not address the reported behavior. See the follow-up verification below.

### Follow-up verification (2026-10-05)

- The live site still serves the old Python/RIFT v3.1 copy described above.
- GitHub recheck confirms website `main` is still `fe5ff41`, with no open PRs
  and no workflow runs. A fresh fetch of `main` leaves the scratch checkout at
  the same commit.
- The reviewed [GHSA-ch52-4w7c-c8xp advisory](https://github.com/advisories/ghsa-ch52-4w7c-c8xp)
  (CVE-2026-93748) still displays `http-cache-semantics` versions through
  4.2.0 as affected and no patched version. In the website checkout, however,
  `npm audit fix --dry-run` proposed 4.3.0. Applying that update made npm
  report zero vulnerabilities, but source review of the installed 4.3.0 showed
  the same vulnerable control flow: shared responses with unapproved
  `Set-Cookie` headers get a zero freshness lifetime, while `max-stale` can
  still return the stale response. The registry currently lists 4.3.0, but the
  advisory still lists no patched version. Upstream [issue #56](https://github.com/kornelski/http-cache-semantics/issues/56)
  documents this path and is closed as not planned. A current `npm audit` on
  the 4.2.0 lockfile still reports the high-severity issue. I reverted the
  lockfile update; do not treat 4.3.0 or npm's audit result as a verified fix.
- The investigation used a scratch checkout at `/tmp/riftor-website`, with
  `origin/main` at `fe5ff41`. The security update is now on branch
  `codex/http-cache-max-stale-fix`; see the prepared remediation section
  below. The live site has not changed.

## Provider smoke test

A single real Z.ai Coding Plan completion succeeded through Riftor using an
ephemeral agent directory and the explicit Coding Plan endpoint. No assessment
tool ran; no target was contacted. The temporary configuration was removed
and the key was not written to the repository. The user was advised that the
key had been pasted into chat and should be rotated. Never copy or reuse that
credential; do not ask the user to paste a replacement into chat.

## Recommended launch sequence

1. Keep the website's local `http-cache-semantics` patch until upstream
   behavior is verified as fixed, then remove it and rerun audit, tests, and
   build.
2. When deployment is requested, verify how `riftor.dev` is hosted and which
   target is intended. Check the new site copy, links, and rendering before any
   live-domain cutover.
3. Use `5.0.0-alpha.0` to describe the current limited
   feature set accurately; do not present it as a feature-complete
   penetration-testing platform.
4. Decide whether the distribution target is a GitHub release, npm, or both;
   neither has been published. Create a tag, release, or publication only on
   an explicit request.
5. Re-check hosted CI and website deployment status. Publish the package or
   switch the live domain only on an explicit user request.

## Merged launch remediations (2026-10-05)

- Application PR [#8](https://github.com/amanverasia/riftor/pull/8) merged as
  [`a7123ae`](https://github.com/amanverasia/riftor/commit/a7123aea58c5edbe10f97353b958933504ee6f51).
  It updates Pi to 1.0.2, TypeBox to 1.3.34, and Node 22 declarations to
  22.20.5; the lockfile resolves nested `brace-expansion` to 5.0.12. It also
  includes the `5.0.0-alpha.0` changelog/version prep and the test-only
  action-budget window fix. Local `npm test` passed 50/50,
  `npm audit --omit=dev` found zero vulnerabilities, and package/CLI checks
  passed. Post-merge main CI passed in
  [run 37285644109](https://github.com/amanverasia/riftor/actions/runs/37285644109).
- Website PR [#1](https://github.com/amanverasia/riftor-website/pull/1) merged
  as [`6b250f6`](https://github.com/amanverasia/riftor-website/commit/6b250f689afc5666ff52a1f02ced973f417883a7).
  It pins `http-cache-semantics` 4.3.0, applies an idempotent fail-closed
  postinstall patch for the max-stale response-directive bypass, and adds
  regression tests plus CI. Clean `npm ci`, audit, tests, and build passed.
  Post-merge main CI passed in
  [run 37285650022](https://github.com/amanverasia/riftor-website/actions/runs/37285650022).
- Application Dependabot PRs [#5](https://github.com/amanverasia/riftor/pull/5),
  [#6](https://github.com/amanverasia/riftor/pull/6), and
  [#7](https://github.com/amanverasia/riftor/pull/7) remain open but are
  superseded by #8; they have not been merged or closed.
- No package release or publication, website deployment, domain, DNS, or
  hosting changes were made.

## Security and verification constraints

Continue following [`AGENTS.md`](../AGENTS.md) and
[`THREAT_MODEL.md`](THREAT_MODEL.md). Every assessment network action must go
through `src/security/action-gateway.ts`. Tests must use local fixtures or
injected resolvers/transports and must never scan real targets. Do not weaken
address validation, pinning, redirect restrictions, timeouts, response bounds,
authorization, approval, leases, budgets, or audit behavior to meet launch
deadlines. Never describe local SHA-256 hashes as signatures or Pi as a
sandbox.
