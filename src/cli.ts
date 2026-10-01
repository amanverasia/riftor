#!/usr/bin/env node

import { createAgentSession } from "@earendil-works/pi-coding-agent";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { randomUUID } from "node:crypto";
import { EngagementStore } from "./engagement/store.js";
import type { Engagement } from "./engagement/types.js";
import { evaluateAction } from "./security/policy.js";
import { normalizeScopeRule, normalizeTarget } from "./security/scope.js";

async function main(): Promise<void> {
  const store = new EngagementStore(process.cwd());
  const { session } = await createAgentSession({
    cwd: process.cwd(),
    noTools: "all",
  });
  const terminal = createInterface({ input: stdin, output: stdout });

  console.log("Riftor — standalone security assessment harness");
  console.log("Pi runtime embedded. Security tools remain disabled during the rebuild.");
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
      if (await handleLocalCommand(input, terminal, store)) continue;

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
): Promise<boolean> {
  if (input === "/help") {
    console.log([
      "Local commands:",
      "  /engagement                 Show the active engagement",
      "  /engagement create <name>   Record authorization and create one",
      "  /scope list                 Show included and excluded targets",
      "  /scope add <target>         Add a host, wildcard, IP, or CIDR",
      "  /scope exclude <target>     Add an explicit exclusion",
      "  /scope remove <target>      Remove a scope rule",
      "  /policy check <target> <activity>  Preview the policy decision",
      "  /exit                       Quit",
    ].join("\n"));
    return true;
  }

  if (input === "/engagement" || input.startsWith("/engagement ")) {
    const [, action, ...rest] = input.split(/\s+/);
    if (action !== "create") {
      const engagement = await store.load();
      console.log(engagement ? formatEngagement(engagement) : "No active engagement.");
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
