import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { writeReport } from "../dist/engagement/report.js";

const packageInfo = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

test("Markdown reports render legacy HTTP evidence without pinned address fields", async () => {
  const directory = await mkdtemp(join(tmpdir(), "riftor-report-compat-"));
  try {
    const engagement = {
      id: "legacy-engagement",
      name: "Legacy engagement",
      createdAt: "2026-01-01T00:00:00.000Z",
      authorization: {
        reference: "AUTH-OLD",
        authorizedBy: "Operator",
        startsAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2027-01-01T00:00:00.000Z",
        activities: ["http_headers"],
      },
      scope: { include: ["example.com"], exclude: [] },
    };
    const evidence = {
      id: "old-evidence",
      engagementId: engagement.id,
      capturedAt: "2026-02-01T00:00:00.000Z",
      target: "example.com",
      activity: "http_headers",
      request: { method: "HEAD", url: "https://example.com/" },
      response: { status: 200, statusText: "OK", headers: { server: "fixture" } },
      previousSha256: null,
      sha256: "legacy-hash",
    };
    const path = await writeReport(directory, "markdown", {
      generatedAt: "2026-10-01T00:00:00.000Z",
      engagement,
      findings: [],
      evidence: [evidence],
    });
    const report = await readFile(path, "utf8");
    assert.match(report, /Connected address: Not recorded by this evidence version/);
    assert.match(report, /Resolved addresses: Not recorded by this evidence version/);
    assert.match(report, /HTTP 200 OK/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("report timestamps cannot escape the reports directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "riftor-report-time-"));
  try {
    await assert.rejects(writeReport(directory, "markdown", {
      generatedAt: "../../outside",
      engagement: {},
      findings: [],
      evidence: [],
    }), /timestamp is invalid/i);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("SARIF 2.1.0 reports preserve finding severity and evidence provenance", async () => {
  const directory = await mkdtemp(join(tmpdir(), "riftor-sarif-report-"));
  try {
    const engagement = {
      id: "sarif-engagement", name: "SARIF engagement", createdAt: "2026-01-01T00:00:00.000Z",
      authorization: { reference: "AUTH-SARIF", authorizedBy: "Operator", startsAt: "2026-01-01T00:00:00.000Z", expiresAt: "2027-01-01T00:00:00.000Z", activities: ["http_headers"] },
      scope: { include: ["example.com"], exclude: [] },
    };
    const finding = {
      id: "finding-sarif", engagementId: engagement.id, createdAt: "2026-02-01T00:00:00.000Z", updatedAt: "2026-02-01T00:00:00.000Z",
      title: "Sensitive header", severity: "high", confidence: "confirmed", status: "open", target: "example.com",
      description: "The server revealed unnecessary information.", remediation: "Remove the header.", evidenceIds: ["evidence-sarif"],
    };
    const acceptedFinding = { ...finding, id: "finding-accepted", title: "Accepted risk", severity: "medium", status: "accepted", evidenceIds: [] };
    const resolvedFinding = { ...finding, id: "finding-resolved", title: "Resolved issue", severity: "low", status: "resolved", evidenceIds: [] };
    const path = await writeReport(directory, "sarif", {
      generatedAt: "2026-10-01T00:00:00.000Z", engagement, findings: [finding, acceptedFinding, resolvedFinding],
      evidence: [{ id: "evidence-sarif", engagementId: engagement.id, activity: "http_headers", target: "example.com", capturedAt: "2026-02-01T00:00:00.000Z", sha256: "abc123" }],
    });
    assert.match(path, /\.sarif\.json$/);
    const sarif = JSON.parse(await readFile(path, "utf8"));
    assert.equal(sarif.$schema, "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json");
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs[0].tool.driver.name, "Riftor");
    assert.equal(sarif.runs[0].tool.driver.semanticVersion, packageInfo.version);
    assert.equal(sarif.runs[0].results.length, 2);
    assert.equal(sarif.runs[0].results[0].level, "error");
    assert.deepEqual(sarif.runs[0].results[0].properties.evidenceIds, ["evidence-sarif"]);
    assert.deepEqual(Object.keys(sarif.runs[0].results[0].partialFingerprints), ["riftorFinding/v1"]);
    assert.match(sarif.runs[0].results[0].partialFingerprints["riftorFinding/v1"], /^[a-f\d]{64}$/);
    assert.equal(sarif.runs[0].results[1].properties.status, "accepted");
    assert.equal(sarif.runs[0].results[1].suppressions[0].status, "accepted");
    assert.equal(sarif.runs[0].properties.evidence[0].sha256, "abc123");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
