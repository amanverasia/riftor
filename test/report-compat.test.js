import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { writeReport } from "../dist/engagement/report.js";

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
