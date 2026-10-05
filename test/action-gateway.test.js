import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { authorizeAction } from "../dist/security/action-gateway.js";
import { reserveActionBudget } from "../dist/security/action-budget.js";

// This test checks persisted limits, not time expiry, so keep its deadline
// well above filesystem and CI scheduling delays.
const testBudget = { targetCooldownMs: 60 * 60_000, maxActions: 2, windowMs: 24 * 60 * 60_000 };

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

test("action budget persists target cooldown and workspace window across store instances", async () => {
  await withTempDir(async (directory) => {
    const active = engagement();
    active.scope.include.push("other.example", "third.example");
    const firstStore = new EngagementStore(directory);
    await firstStore.save(active);
    const evidenceStore = new EvidenceStore(directory);
    const first = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "EXAMPLE.COM.", approvalMessage: "approve" }, {
      engagementStore: firstStore, evidenceStore, approve: async () => true, budgetConfig: testBudget,
    });
    assert.equal(first.allowed, true);
    if (first.allowed) await first.release();

    await firstStore.save(null);
    await firstStore.save({ ...active, id: "another-engagement" });

    const restartedStore = new EngagementStore(directory);
    const cooledDown = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "example.com", approvalMessage: "approve" }, {
      engagementStore: restartedStore, evidenceStore: new EvidenceStore(directory), approve: async () => true, budgetConfig: testBudget,
    });
    assert.equal(cooledDown.allowed, false);
    if (!cooledDown.allowed) assert.match(cooledDown.reason, /Rate limit reached \(target_cooldown\)/);

    const secondTarget = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "other.example", approvalMessage: "approve" }, {
      engagementStore: restartedStore, evidenceStore: new EvidenceStore(directory), approve: async () => true, budgetConfig: testBudget,
    });
    assert.equal(secondTarget.allowed, true);
    if (secondTarget.allowed) await secondTarget.release();

    const globalLimit = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "third.example", approvalMessage: "approve" }, {
      engagementStore: restartedStore, evidenceStore: new EvidenceStore(directory), approve: async () => true, budgetConfig: testBudget,
    });
    assert.equal(globalLimit.allowed, false);
    if (!globalLimit.allowed) assert.match(globalLimit.reason, /Rate limit reached \(workspace_window\)/);

    const audit = await readFile(join(directory, ".riftor", "audit.jsonl"), "utf8");
    assert.match(audit, /"kind":"rate_limited"/);
  });
});

test("action budget fails closed on malformed persistent state", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    await store.save(engagement());
    await writeFile(join(directory, ".riftor", "action-budget.json"), "{broken");
    const result = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "example.com", approvalMessage: "approve" }, {
      engagementStore: store, evidenceStore: new EvidenceStore(directory), approve: async () => true, budgetConfig: testBudget,
    });
    assert.equal(result.allowed, false);
    if (!result.allowed) assert.match(result.reason, /Action budget unavailable/);
  });
});

test("concurrent action requests cannot reserve one remaining budget slot twice", async () => {
  await withTempDir(async (directory) => {
    const firstStore = new EngagementStore(directory);
    await firstStore.save(engagement());
    const run = async (store) => {
      const result = await authorizeAction({ kind: "http_headers", activity: "http_headers", target: "example.com", approvalMessage: "approve" }, {
        engagementStore: store, evidenceStore: new EvidenceStore(directory), approve: async () => true,
        budgetConfig: { targetCooldownMs: 0, maxActions: 1, windowMs: 60_000 },
      });
      if (result.allowed) await result.release();
      return result.allowed;
    };
    const outcomes = await Promise.all([run(firstStore), run(new EngagementStore(directory))]);
    assert.equal(outcomes.filter(Boolean).length, 1);
  });
});

test("action budget enforces exact cooldown expiry and prunes stale reservations", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const release = await store.acquireActionLock();
    const config = { targetCooldownMs: 100, maxActions: 2, windowMs: 1_000 };
    try {
      await assert.rejects(reserveActionBudget(directory, "example.com", "http_headers", { ...config, targetCooldownMs: -1 }, 1_000), /Invalid action budget configuration/);
      assert.deepEqual(await reserveActionBudget(directory, "example.com", "http_headers", config, 1_000), { allowed: true });
      assert.deepEqual(await reserveActionBudget(directory, "example.com", "http_headers", config, 1_099), {
        allowed: false, retryAfterMs: 1, limit: "target_cooldown",
      });
      assert.deepEqual(await reserveActionBudget(directory, "example.com", "http_headers", config, 1_100), { allowed: true });
      assert.deepEqual(await reserveActionBudget(directory, "other.example", "dns_lookup", config, 2_100), { allowed: true });
    } finally {
      await release();
    }
    const persisted = JSON.parse(await readFile(join(directory, ".riftor", "action-budget.json"), "utf8"));
    assert.deepEqual(persisted.reservations, [{ at: 2_100, target: "other.example", activity: "dns_lookup" }]);
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
