import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { createHttpHeadersTool } from "../dist/security/http-headers.js";
import { evaluateAction } from "../dist/security/policy.js";
import { isTargetInScope } from "../dist/security/scope.js";

function engagement(overrides = {}) {
  const startsAt = new Date(Date.now() - 60_000).toISOString();
  return {
    id: "engagement-1",
    name: "test engagement",
    createdAt: startsAt,
    authorization: {
      reference: "AUTH-1",
      authorizedBy: "Operator",
      startsAt,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      activities: ["http_headers"],
    },
    scope: { include: ["example.com"], exclude: [] },
    ...overrides,
  };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("scope matching supports exact hosts, wildcard domains, CIDRs, and exclusions", () => {
  assert.equal(isTargetInScope("example.com", ["example.com"]), true);
  assert.equal(isTargetInScope("sub.example.com", ["*.example.com"]), true);
  assert.equal(isTargetInScope("example.com", ["*.example.com"]), false);
  assert.equal(isTargetInScope("192.0.2.7", ["192.0.2.0/24"]), true);
  assert.equal(isTargetInScope("192.0.3.7", ["192.0.2.0/24"]), false);
  assert.equal(isTargetInScope("admin.example.com", ["*.example.com"], ["admin.example.com"]), false);
});

test("policy requires a live authorization, exact activity, scope, and operator approval", () => {
  const active = engagement();
  const request = { target: "example.com", activity: "http_headers" };
  assert.equal(evaluateAction(active, request).outcome, "approval_required");
  assert.equal(evaluateAction(active, { ...request, humanApproved: true }).outcome, "allow");
  assert.equal(evaluateAction(active, { ...request, approvalAvailable: false }).outcome, "deny");
  assert.equal(evaluateAction(active, { ...request, activity: "port_scan" }).outcome, "deny");
  assert.equal(evaluateAction(active, { ...request, target: "outside.example.net" }).outcome, "deny");
  const expired = engagement({ authorization: { ...active.authorization, expiresAt: new Date(Date.now() - 1).toISOString() } });
  assert.equal(evaluateAction(expired, request).outcome, "deny");
});

test("engagement storage migrates the original format and preserves multiple engagements", async () => {
  await withTempDir(async (directory) => {
    const stateDirectory = join(directory, ".riftor");
    const statePath = join(stateDirectory, "engagement.json");
    const first = engagement();
    await mkdir(stateDirectory, { recursive: true });
    await writeFile(statePath, JSON.stringify({ version: 1, engagement: first }));

    const store = new EngagementStore(directory);
    assert.equal((await store.load())?.id, first.id);
    const second = engagement({ id: "engagement-2", name: "second" });
    await store.save(second);
    assert.deepEqual((await store.list()).map((item) => item.id), [first.id, second.id]);
    assert.equal((await store.load())?.id, second.id);
    assert.equal(await store.activate(first.id), true);
    assert.equal((await store.load())?.id, first.id);
  });
});

test("evidence records form a verifiable hash chain and reject edits", async () => {
  await withTempDir(async (directory) => {
    const store = new EvidenceStore(directory);
    const draft = {
      engagementId: "engagement-1",
      target: "example.com",
      activity: "http_headers",
      request: { method: "HEAD", url: "https://example.com/" },
      response: { status: 200, statusText: "OK", headers: { server: "example" } },
    };
    const first = await store.append(draft);
    const second = await store.append(draft);
    assert.equal(second.previousSha256, first.sha256);
    assert.equal((await store.list()).length, 2);

    const path = join(directory, ".riftor", "evidence.jsonl");
    const lines = (await readFile(path, "utf8")).trimEnd().split("\n");
    const changed = JSON.parse(lines[0]);
    changed.response.status = 201;
    lines[0] = JSON.stringify(changed);
    await writeFile(path, `${lines.join("\n")}\n`);
    await assert.rejects(store.list(), /integrity check failed/);
  });
});

test("the HTTP tool refuses an out-of-scope target before asking for approval", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await store.save(engagement());
    let approvalPrompts = 0;
    const tool = createHttpHeadersTool(store, evidenceStore, async () => {
      approvalPrompts += 1;
      return true;
    });
    const result = await tool.execute("call-1", { target: "203.0.113.8" }, undefined, undefined, {});
    assert.match(result.content[0].text, /Denied: Target is outside engagement scope/);
    assert.equal(approvalPrompts, 0);
  });
});

test("the HTTP tool refuses non-interactive approval before making a request", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await store.save(engagement({ scope: { include: ["203.0.113.8"], exclude: [] } }));
    const tool = createHttpHeadersTool(store, evidenceStore, async () => false);
    const result = await tool.execute("call-2", { target: "203.0.113.8" }, undefined, undefined, {});
    assert.match(result.content[0].text, /operator approval was not granted/);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});
