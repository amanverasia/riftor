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
