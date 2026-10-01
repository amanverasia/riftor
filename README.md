# Riftor

> A standalone cybersecurity assessment harness with Pi embedded as its agent runtime.

Riftor is its own installable CLI. It embeds Pi's TypeScript SDK to run the
agent loop and model integrations inside the Riftor process; users do not need
to install or open Pi separately. Riftor owns engagement authorization, scope
enforcement, controlled security tool integrations, evidence, findings, and
reports.

The product is for authorized security assessments. The initial CLI starts an
embedded Pi session with tools disabled. Assessment actions will be added only
after engagement scope and policy enforcement are in place.

## Development

Requirements: Node.js 22 or newer.

```sh
npm install
npm run build
npm start
```

The complete product and delivery plan is in
[`docs/RESET_PLAN.md`](docs/RESET_PLAN.md).

## Current build

The CLI can record an engagement's authorization, manage exact hosts, wildcard
domains, IPs and CIDRs, and preview policy decisions. Pi's agent tools are
disabled, so no security action can run yet.

```text
/engagement create <name>
/scope add example.com
/scope exclude admin.example.com
/scope list
/policy check example.com passive-review
```

This rewrite is at its bootstrap stage. The previous Python implementation is
preserved in Git history; this branch contains the new standalone CLI.

## Project links

- Website: [riftor.dev](https://riftor.dev)
- Source: [amanverasia/riftor](https://github.com/amanverasia/riftor)
- Website source: [amanverasia/riftor-website](https://github.com/amanverasia/riftor-website)

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
