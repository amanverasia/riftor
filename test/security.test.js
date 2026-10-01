import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { createHttpHeadersTool } from "../dist/security/http-headers.js";
import { createDnsLookupTool } from "../dist/security/dns-lookup.js";
import { createTlsCertificateTool } from "../dist/security/tls-certificate.js";
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

test("engagement storage rejects malformed persisted authorization and inconsistent active IDs", async () => {
  await withTempDir(async (directory) => {
    const stateDirectory = join(directory, ".riftor");
    const statePath = join(stateDirectory, "engagement.json");
    await mkdir(stateDirectory, { recursive: true });
    const store = new EngagementStore(directory);

    // A string looks array-like in JavaScript and can make String#includes grant
    // an activity by substring. Persisted records must keep activities as an array.
    const malformed = engagement();
    malformed.authorization.activities = "prefix-http_headers-suffix";
    await writeFile(statePath, JSON.stringify({
      version: 2,
      activeEngagementId: malformed.id,
      engagements: [malformed],
    }));
    await assert.rejects(store.load(), /Malformed engagement record/);

    // A v2 state must not point at an engagement absent from its records.
    const valid = engagement();
    await writeFile(statePath, JSON.stringify({
      version: 2,
      activeEngagementId: "missing-engagement",
      engagements: [valid],
    }));
    await assert.rejects(store.load(), /Active engagement ID does not exist/);
  });
});

test("a malformed activity string cannot authorize an activity by substring", () => {
  const malformed = engagement();
  malformed.authorization.activities = "prefix-http_headers-suffix";
  const decision = evaluateAction(malformed, {
    target: "example.com",
    activity: "http_headers",
    humanApproved: true,
  });
  assert.equal(decision.outcome, "deny");
  assert.match(decision.reason, /activity/i);
});

test("malformed scope rules fail closed in the policy function", () => {
  const malformed = engagement({ scope: { include: [42], exclude: [] } });
  const decision = evaluateAction(malformed, {
    target: "example.com",
    activity: "http_headers",
    humanApproved: true,
  });
  assert.equal(decision.outcome, "deny");
  assert.match(decision.reason, /scope/i);
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
    assert.match(result.content[0].text, /operator approval was not granted/i);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});

test("the HTTP tool does not connect if authorization expires during target resolution", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    const active = engagement({
      authorization: { ...engagement().authorization, expiresAt: new Date(Date.now() + 200).toISOString() },
    });
    await store.save(active);
    let connectionAttempts = 0;
    const tool = createHttpHeadersTool(store, evidenceStore, async () => true, {
      createResolver: () => ({
        resolve4: async () => {
          await new Promise((resolve) => setTimeout(resolve, 300));
          return ["93.184.216.34"];
        },
        resolve6: async () => [],
        cancel() {},
      }),
      sendHeadRequest: async () => {
        connectionAttempts += 1;
        return { status: 200, statusText: "OK", headers: {} };
      },
    });
    const result = await tool.execute("expired-during-resolution", { target: "example.com" }, undefined, undefined, {});
    assert.match(result.content[0].text, /authorization has expired/i);
    assert.equal(connectionAttempts, 0);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});

test("the DNS tool refuses an out-of-scope name before asking for approval", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await store.save(engagement({ authorization: { ...engagement().authorization, activities: ["dns_lookup"] } }));
    let approvalPrompts = 0;
    const tool = createDnsLookupTool(store, evidenceStore, async () => {
      approvalPrompts += 1;
      return true;
    });
    const result = await tool.execute("call-3", { target: "outside.example.net" }, undefined, undefined, {});
    assert.match(result.content[0].text, /Denied: Target is outside engagement scope/);
    assert.equal(approvalPrompts, 0);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});

test("the TLS certificate tool refuses an out-of-scope hostname before approval or network access", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    const active = engagement({ authorization: { ...engagement().authorization, activities: ["tls_certificate"] } });
    await store.save(active);
    let approvalPrompts = 0;
    const tool = createTlsCertificateTool(store, evidenceStore, async () => {
      approvalPrompts += 1;
      return true;
    });
    const result = await tool.execute("call-tls-out-of-scope", { target: "outside.example.net" }, undefined, undefined, {});
    assert.match(result.content[0].text, /Denied: Target is outside engagement scope/);
    assert.equal(approvalPrompts, 0);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});

test("the TLS tool blocks a private DNS answer unless its IP is explicitly scoped", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    const active = engagement({ authorization: { ...engagement().authorization, activities: ["tls_certificate"] } });
    await store.save(active);
    let connectorCalls = 0;
    const tool = createTlsCertificateTool(store, evidenceStore, async () => true, {
      createResolver: () => ({
        resolve4: async () => ["127.0.0.1"],
        resolve6: async () => [],
        cancel() {},
      }),
      inspectLeaf: async () => {
        connectorCalls += 1;
        throw new Error("connector should not run");
      },
    });
    const result = await tool.execute("tls-private-answer", { target: "example.com" }, undefined, undefined, {});
    assert.match(result.content[0].text, /outside explicit engagement scope/i);
    assert.equal(connectorCalls, 0);
    assert.deepEqual(await evidenceStore.list(), []);
  });
});
