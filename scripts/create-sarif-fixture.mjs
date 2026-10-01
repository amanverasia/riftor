import { copyFile, mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { writeReport } from "../dist/engagement/report.js";

const outputPath = process.argv[2];
if (!outputPath) throw new Error("Usage: node scripts/create-sarif-fixture.mjs <output-file>");

const engagement = {
  id: "sarif-validation-engagement",
  name: "SARIF validation fixture",
  createdAt: "2026-01-01T00:00:00.000Z",
  authorization: {
    reference: "AUTH-SARIF-VALIDATION",
    authorizedBy: "Fixture operator",
    startsAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:00:00.000Z",
    activities: ["http_headers"],
  },
  scope: { include: ["example.com"], exclude: [] },
};

const finding = {
  id: "finding-sarif-validation",
  engagementId: engagement.id,
  createdAt: "2026-02-01T00:00:00.000Z",
  updatedAt: "2026-02-01T00:00:00.000Z",
  title: "Sensitive response header",
  severity: "high",
  confidence: "confirmed",
  status: "open",
  target: "example.com",
  description: "A fixture finding used to check SARIF output compatibility.",
  remediation: "Remove the unnecessary response header.",
  evidenceIds: ["evidence-sarif-validation"],
};

const evidence = {
  id: "evidence-sarif-validation",
  engagementId: engagement.id,
  activity: "http_headers",
  target: "example.com",
  capturedAt: "2026-02-01T00:00:00.000Z",
  sha256: "a".repeat(64),
};

const stagingDirectory = await mkdtemp(join(tmpdir(), "riftor-sarif-validation-"));
try {
  const reportPath = await writeReport(stagingDirectory, "sarif", {
    generatedAt: "2026-10-01T00:00:00.000Z",
    engagement,
    findings: [finding],
    evidence: [evidence],
  });
  const destination = resolve(outputPath);
  await mkdir(dirname(destination), { recursive: true });
  await copyFile(reportPath, destination);
} finally {
  await rm(stagingDirectory, { recursive: true, force: true });
}
