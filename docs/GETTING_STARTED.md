# First run and provider setup

Riftor is an installable CLI with Pi's TypeScript agent runtime embedded. You do
not need to install or launch the separate Pi CLI. Riftor keeps its provider
configuration separate from a personal Pi installation by default.

## Requirements

- Node.js 22.19 or newer
- A credential for a model provider supported by the embedded Pi runtime
- An interactive terminal for model selection and per-action approval

## Install and start

Install the current repository build:

```sh
npm install --global github:amanverasia/riftor
```

Use a dedicated working directory for each customer or assessment. Engagement
records, audit events, evidence, findings, and reports are stored in its local
`.riftor/` directory. The following workspace commands use macOS/Linux shell
syntax.

```sh
mkdir -p ~/riftor-workspaces/acme-assessment
cd ~/riftor-workspaces/acme-assessment
riftor
```

Starting Riftor makes no assessment network requests. Add authorization and
scope before asking the agent to run a check.

## Configure a model provider

Provide a supported API key in the environment before starting Riftor. Common
provider variables include `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and
`GEMINI_API_KEY`; the embedded runtime's `/models` output shows which models are
available with the credentials and model configuration it can see. Use your OS
credential manager or another private method to set secrets. Do not put a real
key in a command saved to shell history, a workspace file, or a Git repository.
See [Pi's provider authentication guide](https://pi.dev/docs/latest/providers)
for provider-specific variables and authentication formats.

Riftor does not expose Pi's interactive `/login` or `/logout` commands. For
file-based Pi SDK authentication, it reads `auth.json` and optional
`models.json` from its agent directory:

- Default: `~/.riftor/agent/`
- Override: set `RIFTOR_AGENT_DIR` to a private directory before starting Riftor

`auth.json` can contain API keys or OAuth tokens; protect it as a secret and do
not commit it. Riftor does not automatically read your personal `~/.pi/agent/`
directory. Keeping the default directory separate avoids sharing credentials
and settings by accident. Riftor also disables discovery of Pi extensions,
skills, prompt templates, themes, and project context files.

The `RIFTOR_AGENT_DIR` override is passed as a resolved filesystem path; use an
absolute path if you set it directly in your environment.

After starting Riftor:

```text
/models
/model <provider/model shown by /models>
```

Restart Riftor after changing environment credentials or `RIFTOR_AGENT_DIR`.
If `/models` is empty, check that the credential is available to the process
and that any custom provider configuration is in the selected agent directory.

## Create an authorized engagement

In Riftor, create an engagement. It will ask for the written authorization
reference, authorizing party, expiration time, and permitted activities.

```text
/engagement create Acme staging assessment
```

Enter only activities covered by the authorization, from `http_headers`,
`dns_lookup`, and `tls_certificate`. Then add the narrowest practical target
scope and any exclusions:

```text
/scope add staging.example.com
/scope exclude admin.staging.example.com
/scope list
/policy check staging.example.com http_headers
```

The policy check previews the decision; it does not contact the target. Each
actual network check requires a live, unexpired engagement, a matching allowed
activity, an in-scope target, and a separate interactive approval. HTTP and TLS
connect to validated addresses; redirects are not followed.

Use `/evidence list` to inspect captured observations, `/findings list` to
review findings, and `/report markdown` or `/report json` to export a report.
Reports are written under `.riftor/reports/`. You can also export the workspace
with `/archive export <path>`; archives include engagements, evidence, and
findings, but not credentials, local audit logs, generated reports, or action
budget history.

For the security boundaries and limitations, see the
[threat model](THREAT_MODEL.md). The full product plan is in
[RESET_PLAN.md](RESET_PLAN.md).
