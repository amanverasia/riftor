#!/usr/bin/env node

import { createAgentSession } from "@earendil-works/pi-coding-agent";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { randomUUID } from "node:crypto";
import { FindingStore } from "./engagement/finding-store.js";
import type { Finding, FindingConfidence, FindingSeverity, FindingStatus } from "./engagement/findings.js";
import { EvidenceStore } from "./engagement/evidence-store.js";
import { writeReport } from "./engagement/report.js";
import { EngagementStore } from "./engagement/store.js";
import type { Engagement } from "./engagement/types.js";
import { evaluateAction } from "./security/policy.js";
import { normalizeScopeRule, normalizeTarget } from "./security/scope.js";
import { createHttpHeadersTool } from "./security/http-headers.js";

async function main(): Promise<void> {
  const store = new EngagementStore(process.cwd());
  const evidenceStore = new EvidenceStore(process.cwd());
  const findingStore = new FindingStore(process.cwd());
  const terminal = createInterface({ input: stdin, output: stdout });
  const httpHeadersTool = createHttpHeadersTool(store, evidenceStore, async (message) => {
    if (!stdin.isTTY || !stdout.isTTY) return false;
    const answer = await terminal.question(`${message} [yes/no] `);
    return answer.trim().toLowerCase() === "yes";
  });
  let session: Awaited<ReturnType<typeof createAgentSession>>["session"];
  try {
    ({ session } = await createAgentSession({
      cwd: process.cwd(),
      tools: [httpHeadersTool.name],
      customTools: [httpHeadersTool],
    }));
  } catch (error) {
    terminal.close();
    throw error;
  }

  console.log("Riftor — standalone security assessment harness");
  console.log("Pi runtime embedded. Only Riftor's approval-gated HTTP headers check is enabled.");
  console.log("Use /help for engagement and scope commands. Type /exit to quit.\n");

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
      if (await handleLocalCommand(input, terminal, store, evidenceStore, findingStore)) continue;

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
): Promise<boolean> {
  if (input === "/help") {
    console.log([
      "Local commands:",
      "  /engagement                 Show the active engagement",
      "  /engagement create <name>   Record authorization and create one",
      "                              Include http_headers in its authorized activities to use the HTTP check",
      "  /engagement list            List saved engagements",
      "  /engagement use <id>        Select an engagement without deleting others",
      "  /scope list                 Show included and excluded targets",
      "  /scope add <target>         Add a host, wildcard, IP, or CIDR",
      "  /scope exclude <target>     Add an explicit exclusion",
      "  /scope remove <target>      Remove a scope rule",
      "  /policy check <target> <activity>  Preview the policy decision",
      "  /evidence list              Inspect captured HTTP check evidence",
      "  /finding add <title>        Record a reviewed finding linked to evidence",
      "  /finding status <id> <state>  Update a finding (open/resolved/accepted)",
      "  /findings list              List findings for the active engagement",
      "  /report markdown|json       Export an engagement report",
      "  /exit                       Quit",
    ].join("\n"));
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
      console.log([
        `${record.id}  ${record.capturedAt}  ${record.activity}  ${record.target}`,
        `  HTTP ${record.response.status} ${record.response.statusText}`,
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

  if (input === "/report markdown" || input === "/report json") {
    const format = input.endsWith("json") ? "json" : "markdown";
    await generateReport(format, store, evidenceStore, findingStore);
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
  const findings = await findingStore.list();
  findings.push(finding);
  await findingStore.save(findings);
  await store.appendAudit({ kind: "finding_created", engagementId: engagement.id, findingId: finding.id, evidenceIds: finding.evidenceIds });
  console.log(`Recorded finding ${finding.id} for ${finding.target}.`);
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
  const findings = await findingStore.list();
  const finding = findings.find((item) => item.id === id && item.engagementId === engagement.id);
  if (!finding) {
    console.log("Finding not found in the active engagement.");
    return;
  }
  finding.status = rawStatus as FindingStatus;
  finding.updatedAt = new Date().toISOString();
  await findingStore.save(findings);
  await store.appendAudit({ kind: "finding_status_updated", engagementId: engagement.id, findingId: id, status: finding.status });
  console.log(`Finding ${id} marked ${finding.status}.`);
}

async function generateReport(
  format: "markdown" | "json",
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

  const bucket = action === "exclude" ? engagement.scope.exclude : engagement.scope.include;
  if (action === "remove") {
    engagement.scope.include = engagement.scope.include.filter((item) => item !== rule);
    engagement.scope.exclude = engagement.scope.exclude.filter((item) => item !== rule);
  } else if (!bucket.includes(rule)) {
    bucket.push(rule);
  }
  await store.save(engagement);
  await store.appendAudit({ kind: "scope_updated", engagementId: engagement.id, action, rule });
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
