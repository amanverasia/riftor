import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { authorizeAction } from "../dist/security/action-gateway.js";

function engagement() {
  const now = Date.now();
  return {
    id: "action-test",
    name: "action test",
    createdAt: new Date(now).toISOString(),
    authorization: {
      reference: "AUTH-1",
      authorizedBy: "Operator",
      startsAt: new Date(now - 10_000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      activities: ["http_headers"],
    },
    scope: { include: ["example.com"], exclude: [] },
  };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-gateway-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("action gateway rechecks scope after the operator prompt", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    const active = engagement();
    await store.save(active);
    const authorization = await authorizeAction({
      kind: "http_headers",
      activity: "http_headers",
      target: "example.com",
      approvalMessage: "approve",
    }, {
      engagementStore: store,
      evidenceStore,
      approve: async () => {
        active.scope.include = [];
        await store.save(active);
        return true;
      },
    });

    assert.deepEqual(authorization, { allowed: false, reason: "Target is outside engagement scope" });
    const audit = await readFile(join(directory, ".riftor", "audit.jsonl"), "utf8");
    assert.match(audit, /"kind":"http_headers_denied"/);
  });
});

test("action lease blocks engagement changes until the authorized action releases it", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await store.save(engagement());
    const authorization = await authorizeAction({
      kind: "http_headers",
      activity: "http_headers",
      target: "example.com",
      approvalMessage: "approve",
      auditDetails: { kind: "spoofed", target: "outside.example", engagementId: "spoofed" },
    }, { engagementStore: store, evidenceStore, approve: async () => true });
    assert.equal(authorization.allowed, true);
    if (!authorization.allowed) return;

    const audit = await readFile(join(directory, ".riftor", "audit.jsonl"), "utf8");
    const started = JSON.parse(audit.trim().split("\n").at(-1));
    assert.equal(started.kind, "http_headers_started");
    assert.equal(started.target, "example.com");
    assert.equal(started.engagementId, "action-test");

    let updateFinished = false;
    const update = store.save({ ...engagement(), id: "next-engagement" }).then(() => { updateFinished = true; });
    await new Promise((resolve) => setTimeout(resolve, 60));
    assert.equal(updateFinished, false);
    await authorization.release();
    await update;
    assert.equal(updateFinished, true);
  });
});

test("action gateway rechecks authorization expiry immediately before network work", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await store.save(engagement());
    const authorization = await authorizeAction({
      kind: "http_headers",
      activity: "http_headers",
      target: "example.com",
      approvalMessage: "approve",
    }, { engagementStore: store, evidenceStore, approve: async () => true });
    assert.equal(authorization.allowed, true);
    if (!authorization.allowed) return;

    authorization.engagement.authorization.expiresAt = new Date(Date.now() - 1).toISOString();
    assert.match(await authorization.recheck() ?? "", /expired/i);
    await authorization.release();
  });
});

test("concurrent evidence appends serialize into one valid hash chain", async () => {
  await withTempDir(async (directory) => {
    const store = new EvidenceStore(directory);
    const draft = {
      engagementId: "action-test",
      target: "example.com",
      activity: "http_headers",
      request: { method: "HEAD", url: "https://example.com/", resolvedAddresses: ["93.184.216.34"], connectedAddress: "93.184.216.34" },
      response: { status: 200, statusText: "OK", headers: {} },
    };
    await Promise.all(Array.from({ length: 8 }, () => store.append(draft)));
    const records = await store.list();
    assert.equal(records.length, 8);
    for (let index = 1; index < records.length; index += 1) {
      assert.equal(records[index].previousSha256, records[index - 1].sha256);
    }
  });
});
