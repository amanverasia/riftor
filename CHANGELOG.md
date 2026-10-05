# Changelog

## 5.0.0-alpha.0 — prepared 2026-10-05 (not published)

This is the first alpha of Riftor's standalone, Pi-powered rebuild. Riftor
embeds Pi's TypeScript agent runtime and provides its own CLI, engagement
authorization, policy enforcement, evidence, findings, and reporting.

### Included

- Engagement records with authorization details, expiration, exact host and
  domain scope, IP/CIDR scope, exclusions, and policy previews.
- Three approval-gated observations: HTTP `HEAD` header inspection, DNS A/AAAA
  lookup, and TLS leaf-certificate inspection. Each requires an active,
  unexpired engagement, matching authorized activity, an in-scope target, and
  interactive approval.
- A central action gateway with validated-address pinning for HTTP and TLS,
  redirect restrictions, persistent rate limits, audit records, and evidence
  capture.
- Operator-reviewed findings, exact-duplicate review, Markdown/JSON/SARIF
  reports, and JSON workspace archive export/import.

### Limitations

- This alpha supports only the three observations listed above. It does not
  provide a port scanner, exploit runner, arbitrary shell or file tools,
  vulnerability database integration, MCP/skills integrations, remote backup,
  or multi-user access control.
- Assess only systems covered by explicit authorization. Every network check
  requires operator approval; starting Riftor makes no assessment request.
- Pi and installed packages run with the host process's permissions. The Pi
  runtime is not a sandbox. Local SHA-256 evidence links detect accidental
  changes but are not signatures.

### Requirements and distribution

- Node.js 22.19 or newer.
- The npm package and a versioned GitHub release have not been published.
  Installation instructions will be finalized with the release channel.
