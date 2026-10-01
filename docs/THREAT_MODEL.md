# Riftor threat model

This document describes the security boundaries in the current Riftor build. It
is a practical guide for operators and contributors, not a claim that the
application is a sandbox or a certified security product.

## What Riftor protects

Riftor is designed to reduce accidental or model-initiated activity outside an
operator's recorded authorization. It requires a live engagement, a matching
activity, an in-scope target, and an interactive approval for every built-in
network check. The policy is enforced in each tool adapter immediately before
the action. The active engagement is locked while a check runs so another Riftor
process cannot change it midway through that check.

HTTP and TLS checks resolve hostnames, reject private or special-use addresses
unless an IP or CIDR is explicitly in scope, and connect to the validated
address while retaining the hostname for the HTTP Host header or TLS SNI and
certificate-name check. HTTP sends one HEAD request to a standard port, follows
no redirect, limits captured headers, and closes the response after reading its
headers. The TLS check performs one handshake on port 443 and sends no
application data. DNS lookup returns a bounded set of A and AAAA records.

Successful observations are stored in a local SHA-256-linked evidence file.
Engagement state, audit records, findings, and reports are stored beneath
`.riftor/` with owner-only file and directory permissions where supported. The
shared action gateway allows up to 60 network checks per rolling workspace
minute and applies a two-second cooldown for the same normalized target and
activity across engagements and processes. Each approved attempt reserves a
slot before network work, so failures and cancellations still count. Budget
state is local to the workspace and is not included in portable archives. It is
a pacing guard, not a tamper-resistant quota: the local owner can edit it, and
system-clock changes can affect its rolling windows.
Markdown reports escape operator- and target-supplied values before rendering.
Workspace archives export engagements, evidence, and findings. Imports validate
records into a staging directory and activate no engagement automatically.
Archives omit local audit logs, generated reports, and Pi provider credentials.

## Trust boundaries and assumptions

- **The operator supplies authorization and scope.** Riftor records what the
  operator enters; it does not verify contracts, ownership, or the identity of
  the person granting permission.
- **Targets and model output are untrusted.** DNS answers, HTTP headers, and
  certificate fields are observations, never authorization or instructions.
  The agent prompt says this explicitly, while policy checks enforce the action
  boundary independently.
- **The local user and workspace are trusted.** A process with the same OS
  account can read or replace state, audit records, evidence, and reports. File
  permissions reduce exposure to other local users but do not protect against
  the owner, root, malware, or a compromised dependency.
- **Pi and installed code run with the host process's permissions.** Riftor
  disables Pi's shell, file, and default tools and disables discovery of Pi
  extensions, skills, prompts, themes, and project context files. This does not
  sandbox the Pi runtime, Node.js, installed packages, or future Riftor code.
- **Model provider credentials are managed by the operator.** Riftor reads
  environment credentials and its own Pi-compatible configuration under
  `~/.riftor/agent` by default (`RIFTOR_AGENT_DIR` can override this path).

## Evidence and audit limits

The evidence chain detects accidental edits, missing links, and reordering when
Riftor reads the file. It is not a digital signature or an external timestamp.
A local attacker who can rewrite the entire file can also recompute the chain.
The JSONL audit log is useful for local review but is not cryptographically
chained. Reports describe recorded observations and operator-reviewed findings;
they do not independently establish that an assessment was authorized or that a
finding is correct.

## Current limits

- Built-in checks are limited to HTTP headers, DNS A/AAAA lookup, and TLS leaf
  certificate inspection. There is no arbitrary shell, port scanner, exploit,
  credential testing, or vulnerability database integration in this build.
- HTTP and TLS connect to one validated address per action. Riftor does not
  retry every address or infer that all addresses behind a hostname have been
  assessed.
- The TLS diagnostic records whether Node's local trust store accepts the leaf
  and reports certificate metadata. It does not retrieve or validate a complete
  certificate chain as a separate assessment result.
- Provider setup uses environment variables or Pi-compatible configuration
  files; Riftor does not yet provide its own credential-entry wizard.
- Signed evidence, remote backups, multi-user access control, and external audit
  storage are not implemented. Archive SHA-256 checks detect accidental changes
  but are not a signature and do not authenticate the source.
- Policy and state files are local to the current working directory. Operators
  should use a dedicated workspace and protect backups and generated reports.

## Safe operation

Use a dedicated working directory, create a separate engagement for each
authorization, enter the narrowest practical scope and allowed activities, and
review each approval prompt before accepting it. Do not place credentials or
secrets in target names, finding descriptions, or report text. Preserve original
evidence and reports if they are needed for later review, and treat them as
untrusted local files if another process could have modified the workspace.
