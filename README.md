# Riftor

> A standalone cybersecurity assessment harness with Pi embedded as its agent runtime.

Riftor is its own installable CLI. It embeds Pi's TypeScript SDK to run the
agent loop and model integrations inside the Riftor process; users do not need
to install or open Pi separately. Riftor owns engagement authorization, scope
enforcement, controlled security tool integrations, evidence, findings, and
reports.

The product is for authorized security assessments. Pi runs inside Riftor, and
Riftor supplies approval-gated HTTP headers and DNS lookup checks limited to
authorized, in-scope targets.

## Development

Requirements: Node.js 22 or newer and credentials for a supported model provider.

Install the current build directly from GitHub:

```sh
npm install --global github:amanverasia/riftor
riftor
```

No separate Pi CLI is required.

For local development:

```sh
npm install
npm run build
npm test
npm start
```

The complete product and delivery plan is in
[`docs/RESET_PLAN.md`](docs/RESET_PLAN.md).

## Current build

The CLI records an engagement's authorization, manages exact hosts, wildcard
domains, IPs and CIDRs, and previews policy decisions. Each network check
requires its matching authorized activity (`http_headers` or `dns_lookup`), an
in-scope target, and individual operator approval. The HTTP check sends one
`HEAD` request to the standard HTTP or HTTPS port, does not follow redirects,
and does not download a response body. The DNS check queries A and AAAA records
for the selected domain. Pi's built-in shell, file, and other tools remain
disabled.

```text
/engagement create <name>
/engagement list
/engagement use <id>
/scope add example.com
/scope exclude admin.example.com
/scope list
/policy check example.com http_headers
/policy check example.com dns_lookup
/evidence list
/finding add Missing strict transport security
/findings list
/report markdown
```

When creating an engagement, enter `http_headers` and/or `dns_lookup` among the
authorized activities to enable those checks. Starting Riftor makes no
security request.
Each successful check saves the status and selected response headers to
`.riftor/evidence.jsonl` in a SHA-256-linked record chain; `/evidence list`
verifies the chain and displays recent records.
Operators can record severity- and confidence-rated findings tied to evidence,
track each as open, resolved, or accepted, and export a local Markdown or JSON
report with `/report markdown` or `/report json`.

This rewrite is at its bootstrap stage. The previous Python implementation is
preserved in Git history; this branch contains the new standalone CLI.

## Project links

- Website: [riftor.dev](https://riftor.dev)
- Source: [amanverasia/riftor](https://github.com/amanverasia/riftor)
- Website source: [amanverasia/riftor-website](https://github.com/amanverasia/riftor-website)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
