import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { exportWorkspace, importWorkspace } from "../dist/engagement/archive.js";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { FindingStore } from "../dist/engagement/finding-store.js";
import { EngagementStore } from "../dist/engagement/store.js";

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-archive-test-"));
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

function engagement() {
  const startsAt = new Date(Date.now() - 60_000).toISOString();
  return {
    id: "archive-engagement", name: "Archive test", createdAt: startsAt,
    authorization: { reference: "AUTH-ARCHIVE", authorizedBy: "Operator", startsAt, expiresAt: new Date(Date.now() + 60_000).toISOString(), activities: ["http_headers"] },
    scope: { include: ["example.com"], exclude: [] },
  };
}

test("workspace archive round trip preserves records while requiring explicit reactivation", async () => {
  await withTempDir(async (source) => {
    const active = engagement();
    const engagements = new EngagementStore(source);
    const evidenceStore = new EvidenceStore(source);
    const findingStore = new FindingStore(source);
    await engagements.save(active);
    const evidence = await evidenceStore.append({
      activity: "http_headers", engagementId: active.id, target: "example.com",
      request: { method: "HEAD", url: "https://example.com/", resolvedAddresses: ["93.184.216.34"], connectedAddress: "93.184.216.34" },
      response: { status: 200, statusText: "OK", headers: { server: "example" } },
    });
    const at = new Date().toISOString();
    await findingStore.save([{
      id: "finding-1", engagementId: active.id, createdAt: at, updatedAt: at, title: "Observed header",
      severity: "info", confidence: "confirmed", status: "open", target: "example.com", description: "Review the server header.",
      remediation: "Remove unnecessary disclosure.", evidenceIds: [evidence.id],
    }]);
    const archivePath = join(source, "workspace.riftor.json");
    await exportWorkspace(source, archivePath);

    const destination = await mkdtemp(join(tmpdir(), "riftor-archive-dest-"));
    try {
      assert.deepEqual(await importWorkspace(destination, archivePath), { engagements: 1, evidence: 1, findings: 1 });
      const restoredEngagements = new EngagementStore(destination);
      assert.equal(await restoredEngagements.load(), null);
      assert.equal((await restoredEngagements.list())[0].id, active.id);
      assert.deepEqual(await new EvidenceStore(destination).list(), await evidenceStore.list());
      assert.deepEqual(await new FindingStore(destination).list(), await findingStore.list());
      assert.equal(await restoredEngagements.activate(active.id), true);
    } finally {
      await rm(destination, { recursive: true, force: true });
    }
  });
});

test("workspace import rejects changed archives and existing workspaces without partial writes", async () => {
  await withTempDir(async (source) => {
    await new EngagementStore(source).save(engagement());
    const archivePath = join(source, "workspace.json");
    await exportWorkspace(source, archivePath);
    const parsed = JSON.parse(await readFile(archivePath, "utf8"));
    parsed.engagements[0].name = "tampered";
    const tamperedPath = join(source, "tampered.json");
    await writeFile(tamperedPath, JSON.stringify(parsed));
    const emptyDestination = await mkdtemp(join(tmpdir(), "riftor-archive-empty-"));
    try {
      await assert.rejects(importWorkspace(emptyDestination, tamperedPath), /SHA-256 integrity check failed/);
      await assert.rejects(importWorkspace(source, archivePath), /no existing \.riftor directory/);
    } finally { await rm(emptyDestination, { recursive: true, force: true }); }
  });
});

test("workspace import rejects correctly rehashed evidence with unsupported fields", async () => {
  await withTempDir(async (source) => {
    const current = engagement();
    await new EngagementStore(source).save(current);
    await new EvidenceStore(source).append({
      activity: "http_headers", engagementId: current.id, target: "example.com",
      request: { method: "HEAD", url: "https://example.com/", resolvedAddresses: ["93.184.216.34"], connectedAddress: "93.184.216.34" },
      response: { status: 200, statusText: "OK", headers: {} },
    });
    const path = join(source, "workspace.json");
    await exportWorkspace(source, path);
    const archive = JSON.parse(await readFile(path, "utf8"));
    const record = archive.evidence[0];
    record.unexpected = { opaque: "data" };
    const { sha256: oldEvidenceHash, ...evidencePayload } = record;
    record.sha256 = createHash("sha256").update(JSON.stringify(evidencePayload)).digest("hex");
    const { sha256: oldArchiveHash, ...archivePayload } = archive;
    archive.sha256 = createHash("sha256").update(canonicalize(archivePayload)).digest("hex");
    const forgedPath = join(source, "forged.json");
    await writeFile(forgedPath, JSON.stringify(archive));

    const destination = await mkdtemp(join(tmpdir(), "riftor-archive-forged-"));
    try {
      await assert.rejects(importWorkspace(destination, forgedPath), /malformed HTTP observation/);
      await assert.rejects(readFile(join(destination, ".riftor", "engagement.json")));
    } finally { await rm(destination, { recursive: true, force: true }); }
  });
});

test("workspace import enforces its file-size limit before reading an oversized archive", async () => {
  await withTempDir(async (directory) => {
    const oversized = join(directory, "oversized.json");
    await writeFile(oversized, "");
    await truncate(oversized, 64 * 1024 * 1024 + 1);
    await assert.rejects(importWorkspace(directory, oversized), /supported regular file/);
  });
});

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
