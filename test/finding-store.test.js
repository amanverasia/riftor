import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FindingStore } from "../dist/engagement/finding-store.js";

function makeFinding(id = "finding-1") {
  const now = new Date().toISOString();
  return {
    id,
    engagementId: "engagement-1",
    createdAt: now,
    updatedAt: now,
    title: "Exposed response header",
    severity: "low",
    confidence: "confirmed",
    status: "open",
    target: "example.com",
    description: "The response exposes a server header.",
    remediation: "Remove or normalize the header.",
    evidenceIds: ["evidence-1"],
  };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-finding-store-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("finding update serializes concurrent changes across store instances", async () => {
  await withTempDir(async (directory) => {
    const stores = Array.from({ length: 6 }, () => new FindingStore(directory));
    await Promise.all(Array.from({ length: 60 }, (_, index) =>
      stores[index % stores.length].update((findings) => {
        findings.push(makeFinding(`finding-${index}`));
      }),
    ));
    const findings = await stores[0].list();
    assert.equal(findings.length, 60);
    assert.equal(new Set(findings.map((finding) => finding.id)).size, 60);
  });
});

test("finding store validates on save and leaves previous state intact on invalid update", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const valid = makeFinding();
    await store.save([valid]);
    const baseline = await store.list();

    await assert.rejects(store.save([{ ...valid, severity: "urgent" }]), /severity is invalid/i);
    await assert.rejects(store.update((findings) => {
      findings[0].title = "x".repeat(257);
    }), /title must be a valid string/i);
    assert.deepEqual(await store.list(), baseline);
  });
});

test("finding store fails closed on malformed persisted records", async () => {
  await withTempDir(async (directory) => {
    const stateDir = join(directory, ".riftor");
    await mkdir(stateDir, { recursive: true });
    const store = new FindingStore(directory);
    await writeFile(join(stateDir, "findings.json"), JSON.stringify({
      version: 1,
      findings: [{ ...makeFinding(), activities: "xhttp_headerssuffix" }],
    }));
    await assert.rejects(store.list(), /missing or unsupported fields/i);
    await assert.rejects(store.update((findings) => findings), /missing or unsupported fields/i);
  });
});

test("finding store rejects malformed JSON and oversized persisted state", async () => {
  await withTempDir(async (directory) => {
    const stateDir = join(directory, ".riftor");
    await mkdir(stateDir, { recursive: true });
    const path = join(stateDir, "findings.json");
    const store = new FindingStore(directory);
    await writeFile(path, "{");
    await assert.rejects(store.list(), /invalid JSON/i);
    await writeFile(path, " ".repeat(8 * 1024 * 1024 + 1));
    await assert.rejects(store.list(), /exceeds/i);
  });
});

test("update returns a detached copy and persists the mutator result", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const returned = await store.update((findings) => [...findings, makeFinding()]);
    returned[0].evidenceIds.push("mutated-after-return");
    assert.deepEqual((await store.list())[0].evidenceIds, ["evidence-1"]);
    const raw = JSON.parse(await readFile(join(directory, ".riftor", "findings.json"), "utf8"));
    assert.equal(raw.version, 1);
  });
});

test("finding duplicate identity normalizes target and title, then merges only new evidence", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const original = { ...makeFinding(), status: "accepted" };
    await store.createOrMerge(original);
    const candidate = {
      ...makeFinding("finding-2"),
      title: "  EXPOSED   response HEADER ",
      target: "EXAMPLE.COM.",
      severity: "critical",
      confidence: "low",
      description: "Updated description that should not overwrite the reviewed finding.",
      remediation: "Different remediation text.",
      evidenceIds: ["evidence-2", "evidence-1"],
    };

    const duplicate = await store.createOrMerge(candidate);
    assert.equal(duplicate.kind, "duplicate");
    assert.deepEqual(duplicate.matches.map((finding) => finding.id), [original.id]);
    assert.deepEqual(await store.list(), [original]);

    const merged = await store.createOrMerge(candidate, { kind: "merge", findingId: original.id });
    assert.equal(merged.kind, "merged");
    assert.deepEqual(merged.addedEvidenceIds, ["evidence-2"]);
    assert.equal(merged.finding.id, original.id);
    assert.equal(merged.finding.status, "accepted");
    assert.equal(merged.finding.severity, original.severity);
    assert.equal(merged.finding.description, original.description);
    assert.deepEqual(merged.finding.evidenceIds, ["evidence-1", "evidence-2"]);
    assert.equal((await store.list()).length, 1);
  });
});

test("identical findings in different engagements do not match and separate creation is explicit", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const original = makeFinding();
    await store.createOrMerge(original);
    const otherEngagement = { ...makeFinding("finding-other-engagement"), engagementId: "engagement-2" };
    assert.equal((await store.createOrMerge(otherEngagement)).kind, "created");

    const intentionalDuplicate = makeFinding("finding-distinct");
    const result = await store.createOrMerge(intentionalDuplicate, { kind: "separate" });
    assert.equal(result.kind, "created");
    assert.equal((await store.list()).length, 3);
  });
});

test("concurrent identical adds return a duplicate candidate instead of silently duplicating", async () => {
  await withTempDir(async (directory) => {
    const stores = [new FindingStore(directory), new FindingStore(directory)];
    const [left, right] = await Promise.all([
      stores[0].createOrMerge(makeFinding("finding-left")),
      stores[1].createOrMerge(makeFinding("finding-right")),
    ]);
    assert.deepEqual([left.kind, right.kind].sort(), ["created", "duplicate"]);
    assert.equal((await stores[0].list()).length, 1);
  });
});

test("status review records transitions without changing evidence and ignores no-op updates", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const original = makeFinding();
    await store.save([original]);

    const unchanged = await store.setStatus(original.engagementId, original.id, "open");
    assert.equal(unchanged.kind, "unchanged");
    if (unchanged.kind !== "unchanged") throw new Error("Expected unchanged status");
    assert.equal(unchanged.finding.updatedAt, original.updatedAt);

    const updated = await store.setStatus(original.engagementId, original.id, "resolved");
    assert.equal(updated.kind, "updated");
    if (updated.kind !== "updated") throw new Error("Expected status transition");
    assert.equal(updated.previousStatus, "open");
    assert.equal(updated.finding.status, "resolved");
    assert.deepEqual(updated.finding.evidenceIds, original.evidenceIds);
    assert.ok(Date.parse(updated.finding.updatedAt) >= Date.parse(original.updatedAt));

    assert.equal((await store.setStatus("another-engagement", original.id, "accepted")).kind, "not_found");
  });
});

test("evidence merge limits fail without replacing the original finding", async () => {
  await withTempDir(async (directory) => {
    const store = new FindingStore(directory);
    const original = { ...makeFinding(), evidenceIds: Array.from({ length: 100 }, (_, index) => `evidence-${index}`) };
    await store.save([original]);
    const candidate = { ...makeFinding("finding-2"), evidenceIds: ["new-evidence"] };

    await assert.rejects(
      store.createOrMerge(candidate, { kind: "merge", findingId: original.id }),
      /evidenceIds must contain at most 100/i,
    );
    assert.deepEqual(await store.list(), [original]);
  });
});
