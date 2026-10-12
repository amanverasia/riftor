import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { acquireFileLock, withFileLock } from "../dist/engagement/file-lock.js";
import { assertWorkspaceReady } from "../dist/engagement/workspace-guard.js";
import { findingFingerprint, findingIdentity } from "../dist/engagement/finding-identity.js";

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-lock-guard-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("file lock serializes holders and removes the lock file on release", async () => {
  await withTempDir(async (directory) => {
    const lockPath = join(directory, ".riftor", "engagement.lock");
    const release = await acquireFileLock(lockPath);
    let secondAcquired = false;
    const second = acquireFileLock(lockPath).then(async (releaseSecond) => {
      secondAcquired = true;
      await releaseSecond();
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(secondAcquired, false);
    await release();
    await second;
    assert.equal(secondAcquired, true);
    await assert.rejects(readFile(lockPath, "utf8"), /ENOENT/);
  });
});

test("withFileLock returns the action result and frees the lock after an error", async () => {
  await withTempDir(async (directory) => {
    const lockPath = join(directory, ".riftor", "engagement.lock");
    assert.equal(await withFileLock(lockPath, async () => 42), 42);
    await assert.rejects(withFileLock(lockPath, async () => { throw new Error("boom"); }), /boom/);
    assert.equal(await withFileLock(lockPath, async () => "free"), "free");
  });
});

test("file lock reclaims a stale lock left by a dead process", async () => {
  await withTempDir(async (directory) => {
    await mkdir(join(directory, ".riftor"), { recursive: true });
    const lockPath = join(directory, ".riftor", "engagement.lock");
    await writeFile(lockPath, JSON.stringify({ pid: 1073741824, createdAt: Date.now() - 200000 }), "utf8");
    const release = await acquireFileLock(lockPath);
    await release();
    await assert.rejects(readFile(lockPath, "utf8"), /ENOENT/);
  });
});

test("workspace guard blocks work while an import marker exists", async () => {
  await withTempDir(async (directory) => {
    await assertWorkspaceReady(directory);
    const marker = join(directory, ".riftor-importing");
    await writeFile(marker, "{}", "utf8");
    await assert.rejects(assertWorkspaceReady(directory), /import is in progress/);
    await rm(marker);
    await assertWorkspaceReady(directory);
  });
});

test("finding identity normalizes target and title, and fingerprints stay stable", async () => {
  const left = findingIdentity({ engagementId: "e1", target: "EXAMPLE.COM.", title: "  Missing   HSTS " });
  const right = findingIdentity({ engagementId: "e1", target: "example.com", title: "missing hsts" });
  assert.equal(left, right);
  assert.notEqual(left, findingIdentity({ engagementId: "e2", target: "example.com", title: "missing hsts" }));
  assert.throws(() => findingIdentity({ engagementId: "e1", target: "example.com", title: "   " }), /empty/);
  const fingerprint = findingFingerprint({ engagementId: "e1", target: "example.com", title: "missing hsts" });
  assert.match(fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(fingerprint, findingFingerprint({ engagementId: "e1", target: "EXAMPLE.COM.", title: "Missing HSTS" }));
});
