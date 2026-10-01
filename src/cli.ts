#!/usr/bin/env node

import { createAgentSession, DefaultResourceLoader } from "@earendil-works/pi-coding-agent";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { FindingStore } from "./engagement/finding-store.js";
import { exportWorkspace, importWorkspace } from "./engagement/archive.js";
import type { Finding, FindingConfidence, FindingSeverity, FindingStatus } from "./engagement/findings.js";
import { EvidenceStore } from "./engagement/evidence-store.js";
import { writeReport } from "./engagement/report.js";
import { EngagementStore } from "./engagement/store.js";
import type { Engagement } from "./engagement/types.js";
import { evaluateAction } from "./security/policy.js";
import { normalizeScopeRule, normalizeTarget } from "./security/scope.js";
import { createHttpHeadersTool } from "./security/http-headers.js";
import { createDnsLookupTool } from "./security/dns-lookup.js";
import { createTlsCertificateTool } from "./security/tls-certificate.js";

async function main(): Promise<void> {
  if (process.argv.slice(2).some((argument) => argument === "--help" || argument === "-h")) {
    console.log([
      "Riftor — standalone security assessment harness",
      "",
      "Usage: riftor [--help]",
      "",
      "Run Riftor interactively. It embeds the Pi agent runtime; no separate Pi CLI is needed.",
      "All network checks require a live engagement, an authorized activity, an in-scope target, and per-action operator approval.",
      "",
      "Start with /help for engagement, scope, evidence, finding, report, and archive commands.",
      "Network activities: http_headers, dns_lookup, tls_certificate",
    ].join("\n"));
    return;
  }
  const store = new EngagementStore(process.cwd());
  const evidenceStore = new EvidenceStore(process.cwd());
  const findingStore = new FindingStore(process.cwd());
  const terminal = createInterface({ input: stdin, output: stdout });
  const requestApproval = async (message: string): Promise<boolean> => {
    if (!stdin.isTTY || !stdout.isTTY) return false;
    const answer = await terminal.question(`${message} [yes/no] `);
    return answer.trim().toLowerCase() === "yes";
  };
  const httpHeadersTool = createHttpHeadersTool(store, evidenceStore, requestApproval);
  const dnsLookupTool = createDnsLookupTool(store, evidenceStore, requestApproval);
  const tlsCertificateTool = createTlsCertificateTool(store, evidenceStore, requestApproval);
  const agentDir = resolve(process.env.RIFTOR_AGENT_DIR ?? join(homedir(), ".riftor", "agent"));
  const resourceLoader = new DefaultResourceLoader({
    cwd: process.cwd(),
    agentDir,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
  });
  let session: Awaited<ReturnType<typeof createAgentSession>>["session"];
  try {
    ({ session } = await createAgentSession({
      cwd: process.cwd(),
      agentDir,
      resourceLoader,
      tools: [httpHeadersTool.name, dnsLookupTool.name, tlsCertificateTool.name],
      customTools: [httpHeadersTool, dnsLookupTool, tlsCertificateTool],
    }));
  } catch (error) {
    terminal.close();
    throw error;
  }

  console.log("Riftor — standalone security assessment harness");
  console.log("Pi runtime embedded. Only Riftor's approval-gated HTTP, DNS, and TLS checks are enabled.");
  console.log(`Model: ${session.model ? `${session.model.provider}/${session.model.id}` : "not selected"}`);
  console.log("Use /help for engagement, model, and scope commands. Type /exit to quit.\n");

  const unsubscribe = session.subscribe((event) => {
    if (
      event.type === "message_update" &&
      event.assistantMessageEvent.type === "text_delta"
    ) {
      process.stdout.write(event.assistantMessageEvent.delta);
    }
  });

  try {
    while (true) {
      const prompt = await terminal.question("riftor> ");
      const input = prompt.trim();
      if (input === "/exit") break;
      if (!input) continue;
      if (await handleLocalCommand(input, terminal, store, evidenceStore, findingStore, session)) continue;

      await session.prompt(prompt);
      process.stdout.write("\n\n");
    }
  } finally {
    unsubscribe();
    terminal.close();
    session.dispose();
  }
}

async function handleLocalCommand(
  input: string,
  terminal: ReturnType<typeof createInterface>,
  store: EngagementStore,
  evidenceStore: EvidenceStore,
  findingStore: FindingStore,
  session: Awaited<ReturnType<typeof createAgentSession>>["session"],
): Promise<boolean> {
  if (input === "/help") {
    console.log([
      "Local commands:",
      "  /models                     List models available with current credentials",
      "  /model <provider/model>     Select a Pi model for this session",
      "  /engagement                 Show the active engagement",
      "  /engagement create <name>   Record authorization and create one",
      "                              Activities: http_headers, dns_lookup, tls_certificate",
      "  /engagement list            List saved engagements",
      "  /engagement use <id>        Select an engagement without deleting others",
      "  /scope list                 Show included and excluded targets",
      "  /scope add <target>         Add a host, wildcard, IP, or CIDR",
      "  /scope exclude <target>     Add an explicit exclusion",
      "  /scope remove <target>      Remove a scope rule",
      "  /policy check <target> <activity>  Preview the policy decision",
      "  /evidence list              Verify and inspect captured evidence",
      "  /finding add <title>        Record a finding and review possible duplicates",
      "  /finding status <id> <state>  Review a finding (open/resolved/accepted)",
      "  /findings list              List findings for the active engagement",
      "  /report markdown|json|sarif Export an engagement report",
      "  /archive export <path>      Export all engagements, evidence, and findings",
      "  /archive import <path>      Import an archive into an empty workspace",
      "  /exit                       Quit",
    ].join("\n"));
    return true;
  }

  if (input === "/models" || input === "/model" || input.startsWith("/model ")) {
    const requested = input.startsWith("/model ") ? input.slice("/model ".length).trim() : "";
    let models;
    try {
      models = await session.modelRuntime.getAvailable();
    } catch (error) {
      console.log(`Model list unavailable: ${error instanceof Error ? error.message : "provider configuration error"}`);
      return true;
    }
    if (!requested) {
      if (!models.length) {
        console.log("No authenticated models are available. Set a supported provider environment variable or configure Pi credentials, then restart Riftor.");
      } else {
        console.log(`Current model: ${session.model ? `${session.model.provider}/${session.model.id}` : "not selected"}`);
        for (const model of models) console.log(`  ${model.provider}/${model.id}  ${model.name}`);
      }
      return true;
    }

    const separator = requested.indexOf("/");
    if (separator < 1 || !requested.slice(separator + 1)) {
      console.log("Usage: /model <provider/model>");
      return true;
    }
    const provider = requested.slice(0, separator);
    const modelId = requested.slice(separator + 1);
    const model = models.find((available) => available.provider === provider && available.id === modelId);
    if (!model) {
      console.log(`Model is unavailable with current credentials: ${requested}. Use /models to list available models.`);
      return true;
    }
    try {
      await session.setModel(model);
      console.log(`Selected model ${model.provider}/${model.id}.`);
    } catch (error) {
      console.log(`Could not select model: ${error instanceof Error ? error.message : "unknown model error"}`);
    }
    return true;
  }

  if (input === "/engagement" || input.startsWith("/engagement ")) {
    const [, action, ...rest] = input.split(/\s+/);
    if (!action) {
      const engagement = await store.load();
      console.log(engagement ? formatEngagement(engagement) : "No active engagement.");
      return true;
    }
    if (action === "list") {
      const engagements = await store.list();
      const active = await store.load();
      if (!engagements.length) console.log("No saved engagements.");
      for (const engagement of engagements) {
        console.log(`${engagement.id === active?.id ? "*" : " "} ${engagement.id}  ${engagement.name}  expires ${engagement.authorization.expiresAt}`);
      }
      return true;
    }
    if (action === "use") {
      const id = rest[0];
      if (!id) {
        console.log("Usage: /engagement use <id>");
        return true;
      }
      if (!await store.activate(id)) {
        console.log("Engagement not found.");
        return true;
      }
      await store.appendAudit({ kind: "engagement_activated", engagementId: id });
      console.log(`Selected engagement ${id}.`);
      return true;
    }
    if (action !== "create") {
      console.log("Usage: /engagement | create <name> | list | use <id>");
      return true;
    }
    const name = rest.join(" ").trim();
    if (!name) {
      console.log("Usage: /engagement create <name>");
      return true;
    }
    await createEngagement(name, terminal, store);
    return true;
  }

  if (input === "/scope" || input.startsWith("/scope ")) {
    await handleScopeCommand(input, store);
    return true;
  }

  if (input === "/evidence" || input === "/evidence list") {
    let records;
    try {
      records = await evidenceStore.list();
    } catch (error) {
      console.log(`Evidence could not be read: ${error instanceof Error ? error.message : "integrity check failed"}`);
      return true;
    }
    if (!records.length) {
      console.log("No evidence captured yet.");
      return true;
    }
    for (const record of records.slice(-20).reverse()) {
      const responseSummary = record.activity === "http_headers"
        ? `HTTP ${record.response.status} ${record.response.statusText}`
        : record.activity === "dns_lookup"
          ? `A ${record.response.A.length} / AAAA ${record.response.AAAA.length}`
          : record.response.certificatePresent
            ? `TLS ${record.response.protocol ?? "unknown"} / ${record.response.authorized ? "trusted" : "certificate warning"}`
            : `TLS connection error`;
      console.log([
        `${record.id}  ${record.capturedAt}  ${record.activity}  ${record.target}`,
        `  ${responseSummary}`,
        `  SHA-256 ${record.sha256}`,
      ].join("\n"));
    }
    if (records.length > 20) console.log(`Showing the latest 20 of ${records.length} records.`);
    return true;
  }

  if (input === "/findings" || input === "/findings list" || input === "/finding list") {
    const engagement = await store.load();
    if (!engagement) {
      console.log("Create an engagement first with /engagement create <name>.");
      return true;
    }
    const findings = (await findingStore.list()).filter((finding) => finding.engagementId === engagement.id);
    if (!findings.length) console.log("No findings recorded for the active engagement.");
    for (const finding of findings) {
      console.log(`${finding.id}  ${finding.severity.toUpperCase()}  ${finding.status}  ${finding.target}  ${finding.title}`);
    }
    return true;
  }

  if (input.startsWith("/finding add ")) {
    await addFinding(input.slice("/finding add ".length).trim(), terminal, store, evidenceStore, findingStore);
    return true;
  }

  if (input.startsWith("/finding status ")) {
    const [, , id, status] = input.split(/\s+/);
    if (!id || !status) {
      console.log("Usage: /finding status <id> <open|resolved|accepted>");
      return true;
    }
    await updateFinding(id, status, store, findingStore);
    return true;
  }

  if (["/report markdown", "/report json", "/report sarif"].includes(input)) {
    const format = input.endsWith("json") ? "json" : input.endsWith("sarif") ? "sarif" : "markdown";
    await generateReport(format, store, evidenceStore, findingStore);
    return true;
  }

  if (input.startsWith("/archive export ")) {
    const path = input.slice("/archive export ".length).trim();
    if (!path) {
      console.log("Usage: /archive export <path>");
      return true;
    }
    try {
      const destination = await exportWorkspace(process.cwd(), path);
      console.log(`Exported workspace archive to ${destination}. Its SHA-256 detects accidental changes but does not prove who created it.`);
    } catch (error) {
      console.log(`Workspace export failed: ${error instanceof Error ? error.message : "unknown error"}`);
    }
    return true;
  }

  if (input.startsWith("/archive import ")) {
    const path = input.slice("/archive import ".length).trim();
    if (!path) {
      console.log("Usage: /archive import <path>");
      return true;
    }
    try {
      const result = await importWorkspace(process.cwd(), path);
      console.log(`Imported ${result.engagements} engagements, ${result.evidence} evidence records, and ${result.findings} findings. No engagement was activated; review authorization and activate one explicitly.`);
    } catch (error) {
      console.log(`Workspace import failed: ${error instanceof Error ? error.message : "unknown error"}`);
    }
    return true;
  }

  if (input.startsWith("/policy check ")) {
    const argumentsText = input.slice("/policy check ".length);
    const separator = argumentsText.indexOf(" ");
    if (separator < 1 || !argumentsText.slice(separator + 1).trim()) {
      console.log("Usage: /policy check <target> <activity>");
      return true;
    }
    let target: string;
    try {
      target = normalizeTarget(argumentsText.slice(0, separator));
    } catch (error) {
      console.log(error instanceof Error ? error.message : "Invalid target");
      return true;
    }
    const activity = argumentsText.slice(separator + 1).trim();
    const engagement = await store.load();
    const decision = evaluateAction(engagement, { target, activity, approvalAvailable: true });
    console.log(`${decision.outcome.toUpperCase()}: ${decision.reason}`);
    await store.appendAudit({ kind: "policy_preview", target, activity, ...decision });
    return true;
  }

  if (input.startsWith("/")) {
    console.log("Unknown local command. Use /help.");
    return true;
  }
  return false;
}

async function addFinding(
  title: string,
  terminal: ReturnType<typeof createInterface>,
  store: EngagementStore,
  evidenceStore: EvidenceStore,
  findingStore: FindingStore,
): Promise<void> {
  const engagement = await store.load();
  if (!engagement) {
    console.log("Create an engagement first with /engagement create <name>.");
    return;
  }
  if (!title) {
    console.log("Usage: /finding add <title>");
    return;
  }

  let evidence;
  try {
    evidence = await evidenceStore.list();
  } catch (error) {
    console.log(`Cannot add a finding: evidence integrity check failed (${error instanceof Error ? error.message : "unknown error"}).`);
    return;
  }
  const evidenceIds = (await terminal.question("Evidence IDs (comma-separated): "))
    .split(",").map((id) => id.trim()).filter(Boolean);
  const selectedEvidence = evidence.filter((item) => evidenceIds.includes(item.id) && item.engagementId === engagement.id);
  if (!evidenceIds.length || selectedEvidence.length !== new Set(evidenceIds).size) {
    console.log("Finding not saved: provide existing evidence IDs from the active engagement.");
    return;
  }
  if (new Set(selectedEvidence.map((item) => item.target)).size !== 1) {
    console.log("Finding not saved: linked evidence must refer to the same target.");
    return;
  }

  const severityText = (await terminal.question("Severity (critical/high/medium/low/info): ")).trim().toLowerCase();
  const confidenceText = (await terminal.question("Confidence (confirmed/high/medium/low): ")).trim().toLowerCase();
  const description = (await terminal.question("Description: ")).trim();
  const remediation = (await terminal.question("Recommended remediation: ")).trim();
  const severities: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];
  const confidences: FindingConfidence[] = ["confirmed", "high", "medium", "low"];
  if (!severities.includes(severityText as FindingSeverity) || !confidences.includes(confidenceText as FindingConfidence) || !description || !remediation) {
    console.log("Finding not saved: severity, confidence, description, and remediation must be valid and non-empty.");
    return;
  }

  const now = new Date().toISOString();
  const finding: Finding = {
    id: randomUUID(),
    engagementId: engagement.id,
    createdAt: now,
    updatedAt: now,
    title,
    severity: severityText as FindingSeverity,
    confidence: confidenceText as FindingConfidence,
    status: "open",
    target: selectedEvidence[0]!.target,
    description,
    remediation,
    evidenceIds: [...new Set(evidenceIds)],
  };

  let result: Awaited<ReturnType<typeof findingStore.createOrMerge>>;
  try {
    result = await findingStore.createOrMerge(finding);
  } catch (error) {
    console.log(`Finding not saved: ${error instanceof Error ? error.message : "storage error"}`);
    return;
  }
  let possibleDuplicateIds: string[] = [];
  while (result.kind === "duplicate") {
    possibleDuplicateIds = result.matches.map((match) => match.id);
    console.log(`Possible duplicate for ${finding.target}: same normalized title and target in this engagement.`);
    for (const match of result.matches) {
      console.log(`  ${match.id}  ${match.severity.toUpperCase()}  ${match.status}  ${match.evidenceIds.length} evidence record(s)  ${match.title}`);
    }
    const choice = (await terminal.question("Type a matching finding ID to merge evidence, `new` to keep a separate finding, or `cancel`: ")).trim();
    if (!choice || choice.toLowerCase() === "cancel") {
      console.log("Finding not saved.");
      return;
    }
    if (choice.toLowerCase() === "new") {
      try {
        result = await findingStore.createOrMerge(finding, { kind: "separate" });
      } catch (error) {
        console.log(`Finding not saved: ${error instanceof Error ? error.message : "storage error"}`);
        return;
      }
      continue;
    }
    if (!result.matches.some((match) => match.id === choice)) {
      console.log("Choose one of the listed finding IDs, `new`, or `cancel`.");
      continue;
    }
    try {
      result = await findingStore.createOrMerge(finding, { kind: "merge", findingId: choice });
    } catch (error) {
      console.log(`Finding not saved: ${error instanceof Error ? error.message : "storage error"}`);
      return;
    }
  }

  if (result.kind === "created") {
    await store.appendAudit({
      kind: "finding_created",
      engagementId: engagement.id,
      findingId: result.finding.id,
      evidenceIds: result.finding.evidenceIds,
      ...(possibleDuplicateIds.length ? { possibleDuplicateFindingIds: possibleDuplicateIds } : {}),
    });
    console.log(`Recorded finding ${result.finding.id} for ${result.finding.target}.`);
    return;
  }

  await store.appendAudit({
    kind: "finding_evidence_merged",
    engagementId: engagement.id,
    findingId: result.finding.id,
    addedEvidenceIds: result.addedEvidenceIds,
    status: result.finding.status,
  });
  if (result.addedEvidenceIds.length) {
    console.log(`Added ${result.addedEvidenceIds.length} evidence record(s) to finding ${result.finding.id}; its ${result.finding.status} status and reviewed details were preserved.`);
  } else {
    console.log(`Finding ${result.finding.id} already includes all selected evidence; no changes were made.`);
  }
}

async function updateFinding(
  id: string,
  rawStatus: string,
  store: EngagementStore,
  findingStore: FindingStore,
): Promise<void> {
  const engagement = await store.load();
  if (!engagement) {
    console.log("Create an engagement first with /engagement create <name>.");
    return;
  }
  const statuses: FindingStatus[] = ["open", "resolved", "accepted"];
  if (!statuses.includes(rawStatus as FindingStatus)) {
    console.log("Status must be open, resolved, or accepted.");
    return;
  }
  const result = await findingStore.setStatus(engagement.id, id, rawStatus as FindingStatus);
  if (result.kind === "not_found") {
    console.log("Finding not found in the active engagement.");
    return;
  }
  if (result.kind === "unchanged") {
    console.log(`Finding ${id} is already ${rawStatus}; no changes were made.`);
    return;
  }
  await store.appendAudit({
    kind: "finding_status_updated",
    engagementId: engagement.id,
    findingId: id,
    previousStatus: result.previousStatus,
    status: result.finding.status,
    evidenceIds: result.finding.evidenceIds,
  });
  console.log(`Finding ${id} marked ${rawStatus}.`);
}

async function generateReport(
  format: "markdown" | "json" | "sarif",
  store: EngagementStore,
  evidenceStore: EvidenceStore,
  findingStore: FindingStore,
): Promise<void> {
  const engagement = await store.load();
  if (!engagement) {
    console.log("Create an engagement first with /engagement create <name>.");
    return;
  }
  try {
    const evidence = (await evidenceStore.list()).filter((item) => item.engagementId === engagement.id);
    const findings = (await findingStore.list()).filter((item) => item.engagementId === engagement.id);
    const generatedAt = new Date().toISOString();
    const path = await writeReport(process.cwd(), format, { generatedAt, engagement, evidence, findings });
    const relativePath = path.slice(process.cwd().length + 1);
    await store.appendAudit({ kind: "report_generated", engagementId: engagement.id, format, path: relativePath });
    console.log(`Wrote ${format} report to ${relativePath}`);
  } catch (error) {
    console.log(`Report was not generated: ${error instanceof Error ? error.message : "unknown error"}`);
  }
}

async function createEngagement(
  name: string,
  terminal: ReturnType<typeof createInterface>,
  store: EngagementStore,
): Promise<void> {
  const reference = (await terminal.question("Written authorization reference: ")).trim();
  const authorizedBy = (await terminal.question("Authorized by: ")).trim();
  const expiresAt = (await terminal.question("Authorization expiry (ISO 8601): ")).trim();
  const activities = (await terminal.question("Authorized activities (comma-separated): "))
    .split(",").map((activity) => activity.trim()).filter(Boolean);

  if (!reference || !authorizedBy || !activities.length || !Number.isFinite(Date.parse(expiresAt))) {
    console.log("Engagement not created: authorization details are incomplete or invalid.");
    return;
  }
  const startsAt = new Date().toISOString();
  if (Date.parse(expiresAt) <= Date.parse(startsAt)) {
    console.log("Engagement not created: expiry must be in the future.");
    return;
  }

  const engagement: Engagement = {
    id: randomUUID(),
    name,
    createdAt: startsAt,
    authorization: { reference, authorizedBy, startsAt, expiresAt: new Date(expiresAt).toISOString(), activities },
    scope: { include: [], exclude: [] },
  };
  await store.save(engagement);
  await store.appendAudit({ kind: "engagement_created", engagementId: engagement.id, name, reference });
  console.log(`Created engagement “${name}”. Add authorized targets with /scope add <target>.`);
}

async function handleScopeCommand(input: string, store: EngagementStore): Promise<void> {
  const [, action, ...rest] = input.split(/\s+/);
  const engagement = await store.load();
  if (!engagement) {
    console.log("Create an engagement first with /engagement create <name>.");
    return;
  }
  if (!action || action === "list") {
    console.log(`Included: ${engagement.scope.include.join(", ") || "(none)"}`);
    console.log(`Excluded: ${engagement.scope.exclude.join(", ") || "(none)"}`);
    return;
  }
  if (!["add", "exclude", "remove"].includes(action)) {
    console.log("Usage: /scope list | add <target> | exclude <target> | remove <target>");
    return;
  }

  const rawTarget = rest.join(" ");
  let rule: string;
  try {
    rule = normalizeScopeRule(rawTarget);
  } catch (error) {
    console.log(error instanceof Error ? error.message : "Invalid scope rule");
    return;
  }

  const updated = await store.updateActive((active) => {
    const bucket = action === "exclude" ? active.scope.exclude : active.scope.include;
    if (action === "remove") {
      active.scope.include = active.scope.include.filter((item) => item !== rule);
      active.scope.exclude = active.scope.exclude.filter((item) => item !== rule);
    } else if (!bucket.includes(rule)) {
      bucket.push(rule);
    }
  }, engagement.id);
  if (!updated) {
    console.log("Active engagement changed; review it and retry the scope update.");
    return;
  }
  await store.appendAudit({ kind: "scope_updated", engagementId: updated.id, action, rule });
  console.log(`Scope ${action}: ${rule}`);
}

function formatEngagement(engagement: Engagement): string {
  return [
    `Engagement: ${engagement.name} (${engagement.id})`,
    `Authorized by: ${engagement.authorization.authorizedBy}`,
    `Reference: ${engagement.authorization.reference}`,
    `Valid until: ${engagement.authorization.expiresAt}`,
    `Activities: ${engagement.authorization.activities.join(", ")}`,
  ].join("\n");
}

main().catch((error: unknown) => {
  console.error("Riftor failed to start:", error);
  process.exitCode = 1;
});
