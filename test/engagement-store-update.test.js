import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EngagementStore } from "../dist/engagement/store.js";

function engagement() {
  const startsAt = new Date(Date.now() - 60_000).toISOString();
  return {
    id: "engagement-update-test",
    name: "update test",
    createdAt: startsAt,
    authorization: {
      reference: "AUTH-UPDATE",
      authorizedBy: "Operator",
      startsAt,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      activities: ["http_headers"],
    },
    scope: { include: ["example.com"], exclude: [] },
  };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-store-update-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("updateActive serializes concurrent read-modify-write calls across store instances", async () => {
  await withTempDir(async (directory) => {
    const firstStore = new EngagementStore(directory);
    const secondStore = new EngagementStore(directory);
    await firstStore.save(engagement());

    await Promise.all(Array.from({ length: 40 }, (_, index) => {
      const store = index % 2 === 0 ? firstStore : secondStore;
      return store.updateActive((active) => {
        active.scope.include.push(`host-${index}.example.com`);
      });
    }));

    const stored = await secondStore.load();
    assert.ok(stored);
    assert.equal(stored.scope.include.length, 41);
    for (let index = 0; index < 40; index += 1) {
      assert.ok(stored.scope.include.includes(`host-${index}.example.com`));
    }
  });
});

test("updateActive validates mutations, preserves the engagement ID, and returns detached data", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    const initial = engagement();
    await store.save(initial);

    await assert.rejects(
      store.updateActive((active) => {
        active.authorization.activities = "prefix-http_headers-suffix";
      }),
      /Malformed engagement record/,
    );
    await assert.rejects(
      store.updateActive((active) => ({ ...active, id: "replacement-id" })),
      /ID cannot be changed/,
    );
    assert.deepEqual(await store.load(), initial);

    const updated = await store.updateActive((active) => {
      active.name = "updated name";
    });
    assert.ok(updated);
    updated.name = "mutated by caller";
    assert.equal((await store.load())?.name, "updated name");
  });
});

test("updateActive returns null and skips the mutator when no engagement is active", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    let called = false;
    assert.equal(await store.updateActive(() => { called = true; }), null);
    assert.equal(called, false);
  });
});

test("updateActive can reject an engagement that became active after the caller read state", async () => {
  await withTempDir(async (directory) => {
    const store = new EngagementStore(directory);
    await store.save(engagement());
    let called = false;
    assert.equal(await store.updateActive(() => { called = true; }, "stale-engagement-id"), null);
    assert.equal(called, false);
    assert.deepEqual((await store.load())?.scope.include, ["example.com"]);
  });
});
