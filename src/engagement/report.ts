import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { HttpHeadersEvidence } from "./evidence.js";
import type { Finding } from "./findings.js";
import type { Engagement } from "./types.js";

export interface ReportData {
  generatedAt: string;
  engagement: Engagement;
  findings: Finding[];
  evidence: HttpHeadersEvidence[];
}

export async function writeReport(
  workdir: string,
  format: "markdown" | "json",
  data: ReportData,
): Promise<string> {
  const directory = join(workdir, ".riftor", "reports");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(join(workdir, ".riftor"), 0o700);
  await chmod(directory, 0o700);
  const timestamp = data.generatedAt.replace(/[:.]/g, "-");
  const path = join(directory, `assessment-${timestamp}.${format === "markdown" ? "md" : "json"}`);
  const content = format === "json" ? `${JSON.stringify(data, null, 2)}\n` : renderMarkdown(data);
  await writeFile(path, content, { mode: 0o600, flag: "wx" });
  await chmod(path, 0o600);
  return path;
}

function renderMarkdown(data: ReportData): string {
  const { engagement } = data;
  const lines = [
    `# Security assessment: ${escapeInline(engagement.name)}`,
    "",
    `- Engagement ID: ${escapeInline(engagement.id)}`,
    `- Generated: ${data.generatedAt}`,
    `- Authorized by: ${escapeInline(engagement.authorization.authorizedBy)}`,
    `- Authorization reference: ${escapeInline(engagement.authorization.reference)}`,
    `- Authorization expires: ${engagement.authorization.expiresAt}`,
    `- Authorized activities: ${engagement.authorization.activities.map(escapeInline).join(", ")}`,
    `- Included scope: ${engagement.scope.include.map(escapeInline).join(", ") || "None"}`,
    `- Excluded scope: ${engagement.scope.exclude.map(escapeInline).join(", ") || "None"}`,
    "",
    "## Findings",
    "",
  ];

  if (!data.findings.length) lines.push("No findings recorded.", "");
  for (const finding of data.findings) {
    lines.push(
      `### ${escapeInline(finding.title)}`,
      "",
      `- ID: ${escapeInline(finding.id)}`,
      `- Severity: ${finding.severity}`,
      `- Confidence: ${finding.confidence}`,
      `- Status: ${finding.status}`,
      `- Target: ${escapeInline(finding.target)}`,
      `- Evidence IDs: ${finding.evidenceIds.map(escapeInline).join(", ")}`,
      "",
      finding.description,
      "",
      `**Remediation:** ${finding.remediation}`,
      "",
    );
  }

  lines.push("## Evidence", "");
  if (!data.evidence.length) lines.push("No evidence captured.", "");
  for (const record of data.evidence) {
    lines.push(
      `### ${escapeInline(record.activity)} — ${escapeInline(record.target)}`,
      "",
      `- ID: ${escapeInline(record.id)}`,
      `- Captured: ${record.capturedAt}`,
      `- Request: ${escapeInline(record.request.method)} ${escapeInline(record.request.url)}`,
      `- Response: HTTP ${record.response.status} ${escapeInline(record.response.statusText)}`,
      `- SHA-256: ${escapeInline(record.sha256)}`,
      "",
    );
    for (const [name, value] of Object.entries(record.response.headers)) {
      lines.push(`- ${escapeInline(name)}: ${escapeInline(value)}`);
    }
    lines.push("");
  }
  lines.push("---", "Generated locally by Riftor. Findings reflect the evidence and review recorded in this engagement.", "");
  return lines.join("\n");
}

function escapeInline(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|<>~-]/g, "\\$&").replace(/[\r\n]+/g, " ");
}
