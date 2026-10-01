# Riftor

> A standalone cybersecurity assessment harness with Pi embedded as its agent runtime.

Riftor is its own installable CLI. It embeds Pi's TypeScript SDK to run the
agent loop and model integrations inside the Riftor process; users do not need
to install or open Pi separately. Riftor owns engagement authorization, scope
enforcement, controlled security tool integrations, evidence, findings, and
reports.

The product is for authorized security assessments. Pi runs inside Riftor, and
Riftor supplies approval-gated HTTP headers, DNS lookup, and TLS certificate
checks limited to authorized, in-scope targets.

## Development

Requirements: Node.js 22.19 or newer and credentials for a supported model
provider. Riftor uses Pi's provider credentials and model configuration, so no
separate Pi CLI installation is required.

Install the current build directly from GitHub:

```sh
npm install --global github:amanverasia/riftor
riftor
```

No separate Pi CLI is required.

Set a provider key in the environment before starting, for example
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY`, then use `/models`
and `/model <provider/model>` inside Riftor. Riftor keeps its Pi model and
credential configuration in `~/.riftor/agent` by default; set `RIFTOR_AGENT_DIR`
to use another location. It does not load Pi extensions, skills, prompts, or
project context into the assessment process. See
[Pi's provider authentication guide](https://pi.dev/docs/latest/providers) for
supported providers and credential setup.

For local development:

```sh
npm install
npm run build
npm test
npm start
```

The complete product and delivery plan is in
[`docs/RESET_PLAN.md`](docs/RESET_PLAN.md).
The current security boundaries and limitations are in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Current build

The CLI records an engagement's authorization, manages exact hosts, wildcard
domains, IPs and CIDRs, and previews policy decisions. Each network check
requires its matching authorized activity (`http_headers`, `dns_lookup`, or
`tls_certificate`), an in-scope target, and individual operator approval. The HTTP check sends one
`HEAD` request to the standard HTTP or HTTPS port, does not follow redirects,
and does not download a response body. The DNS check queries A and AAAA records
for the selected domain. The TLS check inspects leaf certificate metadata on
port 443 without sending application data. HTTP and TLS connections pin to
validated IP addresses; private addresses require an explicit IP/CIDR scope
entry. Pi's built-in shell, file, and other tools remain disabled.

```text
/engagement create <name>
/engagement list
/engagement use <id>
/scope add example.com
/scope exclude admin.example.com
/scope list
/policy check example.com http_headers
/policy check example.com dns_lookup
/policy check example.com tls_certificate
/evidence list
/finding add Missing strict transport security
/findings list
/report markdown|json|sarif
/archive export ./riftor-workspace.json
```

When creating an engagement, enter the authorized activity names among
`http_headers`, `dns_lookup`, and `tls_certificate` to enable those checks.
Starting Riftor makes no security request.
Each successful check saves its observations to `.riftor/evidence.jsonl` in a
SHA-256-linked record chain; `/evidence list` verifies the chain and displays
recent records. Reports preserve older HTTP evidence that predates pinned-IP
recording.
The shared action gateway caps activity at 60 network checks per workspace per
rolling minute and enforces a two-second cooldown for the same normalized
target and activity. The budget persists across restarts and engagements;
failed or cancelled approved attempts still use a slot.
Operators can record severity- and confidence-rated findings tied to evidence,
track each as open, resolved, or accepted, and export a local Markdown or JSON
report with `/report markdown`, `/report json`, or `/report sarif`. SARIF
output uses version 2.1.0 and carries finding metadata plus evidence references
for compatible SARIF consumers ([OASIS SARIF standard](https://www.oasis-open.org/standard/sarifv2-1-os/)). Resolved findings are omitted and accepted findings are marked suppressed. Network targets and evidence stay in Riftor result properties, so file-centric code-scanning interfaces may not display them as locations. `/archive export <path>` saves
all engagements, evidence, and findings as one JSON archive. Import it with
`/archive import <path>` from a workspace with no `.riftor` directory. Imported
engagements stay inactive until selected with `/engagement use`; review their
authorization before running checks. The archive checksum detects accidental
changes but does not authenticate its creator. Archive files do not include
local audit logs, reports, action-budget history, or Pi provider credentials.
To restore an archive, start Riftor in a different workspace that has no
`.riftor` directory, then run `/archive import <path>`.

This rewrite is at its bootstrap stage. The previous Python implementation is
preserved in Git history; this branch contains the new standalone CLI.

## Project links

- Website: [riftor.dev](https://riftor.dev)
- Source: [amanverasia/riftor](https://github.com/amanverasia/riftor)
- Website source: [amanverasia/riftor-website](https://github.com/amanverasia/riftor-website)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
