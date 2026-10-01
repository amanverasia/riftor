# Riftor reset plan

## Product

Riftor is a standalone, local-first cybersecurity assessment harness built on
Pi's TypeScript SDK. Users install and run Riftor directly; they do not need to
install or open Pi separately. Riftor supplies the CLI, engagement workflow,
authorization and scope, tool policy, evidence, findings, and reporting. The Pi
SDK runs the model and agent loop inside the Riftor process.

The product is for security work on systems the operator is authorized to
assess. Its primary quality bar is dependable operator control: every action
must have a clear target, a policy decision, an attributable record, and a
usable result.

## Product principles

- **Authorization comes first.** An engagement records who authorized it, the
  allowed assets and activities, exclusions, and an expiration. No target is
  implicitly in scope.
- **Enforcement sits at the execution boundary.** Prompts and model guidance
  explain policy; they do not enforce it. Every network-capable tool must pass
  through the same policy gateway, including nested and MCP-backed calls.
- **Fail closed.** Unknown targets, malformed scope, expired authorization,
  unavailable policy state, and non-interactive execution block active actions.
- **Least capability by default.** Begin with observation and explicit
  operator-driven workflows. Expose only the tools required for the current
  task. Broad shell access is not the default assessment interface.
- **Evidence before claims.** Findings link to captured evidence and preserve
  provenance, timestamps, target, and the action that produced them. Reports
  distinguish verified results from hypotheses.
- **Local-first and inspectable.** Engagement state and audit records live in
  the workspace, with portable exports and no required hosted service.
- **Pi is the runtime foundation, not the security policy.** Riftor uses Pi's
  extension and SDK contracts while retaining independent, testable policy and
  data modules.

## Architecture

1. **Standalone CLI and Pi runtime** — ship Riftor as its own Node.js executable
   with the Pi SDK as a runtime dependency. Riftor owns startup, input/output,
   engagement selection, and commands; the SDK supplies model and agent
   lifecycle support. Keep security rules independent of terminal rendering.
2. **Engagement core** — typed engagement, authorization, asset, exclusion,
   and lifecycle records. Store them locally and support export/import.
3. **Policy gateway** — classify every action, resolve all requested targets,
   check engagement authorization and exclusions, apply rate and impact limits,
   and produce an allow, deny, or approval decision. Re-check immediately
   before execution to reduce scope-change races.
4. **Tool adapters** — small, typed adapters for security tools and integrations.
   Each declares its capabilities and target extraction rules. Unknown adapters
   are denied. MCP tools must receive the same treatment as built-in tools.
5. **Evidence and findings** — append-only activity and evidence records;
   findings reference evidence IDs and carry severity, confidence, status, and
   remediation. Deduplication and review never erase source evidence.
6. **Reporting** — reproducible Markdown and JSON first, then HTML and SARIF
   where their schemas fit. Reports include scope, timing, limitations, and
   evidence references.

Pi extensions execute with the host process's operating-system permissions.
Therefore extensions and external tool packages are trusted code; installing
them is not a sandbox. Assessment tools need an explicit execution boundary and
must not inherit arbitrary shell access merely because Pi can run shell tools.

## Delivery sequence

### 0. Reset and product contract

- Establish this plan and the new `amanverasia` repository identity.
- Create a standalone TypeScript CLI that embeds the Pi SDK.
- Keep the existing Git history intact so the old Python implementation remains
  recoverable from prior commits while the new runtime takes shape.

### 1. Engagement and authorization core

- Define engagement lifecycle and authorization record formats.
- Implement exact host, domain, IP, and CIDR matching, exclusions, and expiry.
- Add a human-readable scope preview and audit events for policy decisions.
- Make active execution unavailable until an engagement has valid scope.

### 2. Policy-enforced tool runtime

- Add the tool adapter contract and central pre-execution policy gateway.
- Integrate Pi tool-call lifecycle hooks and cover nested tool calls.
- Require visible approval for actions outside the engagement's pre-approved
  activity set; deny by default without an interactive approver.
- Add bounded concurrency, request rate, timeout, and cancellation controls.

Progress: Pi's built-in tools are suppressed, and the embedded runtime uses a
Riftor-owned configuration directory without discovering Pi extensions, skills,
prompts, themes, or project context files. Riftor exposes HTTP `HEAD`, DNS A/AAAA
lookup, and TLS leaf-certificate inspection. Each checks the active engagement,
target scope, its exact authorized activity, and fresh operator confirmation.
HTTP rejects custom ports and redirects. HTTP and TLS pin their connections to
validated IPs; private addresses require explicit IP/CIDR scope. Authorization
is held under a cross-process lease and rechecked immediately before network
activity. All three tools record outcomes in the local audit log and successful
observations in the SHA-256-linked evidence chain, inspectable with `/evidence
list`. A persistent action budget permits at most 60 checks per workspace in a
rolling minute and applies a two-second cooldown per normalized target/activity
pair across engagements and Riftor processes. Failed or cancelled actions still
consume their reservation. Broader lifecycle hooks and centralized adapter
registration remain planned.

Engagement state now retains multiple saved authorizations and lets the operator
select the active one; the previous single-engagement state file migrates when
next written, preserving its existing engagement.

### 3. Evidence and assessment workflow

- Add durable evidence capture, provenance, findings, triage, and deduplication.
- Add operator-reviewed workflows and report generation.
- Start with a small set of well-defined, low-impact integrations, then expand
  only when each adapter has target extraction and policy coverage.

Progress: operators can create and update findings tied to verified evidence,
and export Markdown or JSON reports containing engagement scope, authorization,
findings, and evidence provenance. SARIF 2.1.0 export is available for findings
and evidence references. Report output is stored under `.riftor/reports`
with owner-only permissions. Engagement and finding mutations serialize across
Riftor processes; malformed persisted engagement and finding data fails closed.
Workspace archives now export/import engagements, evidence, and findings with
schema validation and a checksum; imported engagements remain inactive.
Finding deduplication and additional assessment adapters remain planned.

### 4. Extensibility and release

- Add skills and MCP integrations behind the same policy and audit boundary.
- Add migration, backups, and recovery behavior beyond the current JSON workspace archive.
- Document threat model, supported platforms, installation, and safe operation.
- Add CI checks and release packaging for the Pi ecosystem.

## Initial acceptance criteria

- Riftor installs as its own CLI and embeds the Pi SDK as a runtime dependency.
- Starting Riftor alone performs no security scan and makes no network requests.
- Active tool calls cannot run without valid, unexpired engagement scope.
- Every decision and completed action is attributable to an engagement and
  recorded locally.
- The harness behaves safely when scope data is missing, stale, invalid, or when
  approval UI is unavailable.

## Current implementation status

The standalone CLI, local engagement records, authorization expiry checks,
host/domain/IP/CIDR scope matching, exclusions, policy previews, and local audit
records are in place. Three policy-gated adapters for HTTP headers, DNS lookup,
and TLS certificate inspection are wired into Pi; the Pi shell, file, and default
tools stay disabled. Hashed evidence capture, operator-reviewed findings,
Markdown/JSON/SARIF reports, and JSON workspace archives are in place.
Additional adapters and findings deduplication remain planned.

## Repository and website identity

- Application repository: `https://github.com/amanverasia/riftor`
- Website repository: `https://github.com/amanverasia/riftor-website`
- Website domain: `https://riftor.dev`

The application repository is checked out here. The website source is in the
separate `amanverasia/riftor-website` repository. The live domain has not been
redeployed as part of this application reset.

## Pi references

- [Pi documentation](https://pi.dev/docs/latest)
- [SDK](https://pi.dev/docs/latest/sdk)
- [Pi coding agent package](https://www.npmjs.com/package/@earendil-works/pi-coding-agent)
