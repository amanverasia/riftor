import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { EvidenceRecord } from "./evidence.js";
import type { Finding } from "./findings.js";
import type { Engagement } from "./types.js";

export interface ReportData {
  generatedAt: string;
  engagement: Engagement;
  findings: Finding[];
  evidence: EvidenceRecord[];
}

export async function writeReport(
  workdir: string,
  format: "markdown" | "json",
  data: ReportData,
): Promise<string> {
  const generatedAt = new Date(data.generatedAt);
  if (!Number.isFinite(generatedAt.getTime())) throw new Error("Report timestamp is invalid");
  const timestamp = generatedAt.toISOString().replace(/[:.]/g, "-");
  const directory = join(workdir, ".riftor", "reports");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(join(workdir, ".riftor"), 0o700);
  await chmod(directory, 0o700);
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
    `- Generated: ${escapeInline(data.generatedAt)}`,
    `- Authorized by: ${escapeInline(engagement.authorization.authorizedBy)}`,
    `- Authorization reference: ${escapeInline(engagement.authorization.reference)}`,
    `- Authorization expires: ${escapeInline(engagement.authorization.expiresAt)}`,
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
      escapeInline(finding.description),
      "",
      `**Remediation:** ${escapeInline(finding.remediation)}`,
      "",
    );
  }

  lines.push("## Evidence", "");
  if (!data.evidence.length) lines.push("No evidence captured.", "");
  for (const record of data.evidence) {
    const activityDetails = record.activity === "http_headers"
      ? [
          `- Request: ${escapeInline(record.request.method)} ${escapeInline(record.request.url)}`,
          `- Connected address: ${escapeInline(record.request.connectedAddress ?? "Not recorded by this evidence version")}`,
          `- Resolved addresses: ${(record.request.resolvedAddresses ?? []).map(escapeInline).join(", ") || "Not recorded by this evidence version"}`,
          `- Response: HTTP ${record.response.status} ${escapeInline(record.response.statusText)}`,
          ...Object.entries(record.response.headers).map(([name, value]) => `- ${escapeInline(name)}: ${escapeInline(value)}`),
        ]
      : record.activity === "dns_lookup"
      ? [
          `- DNS query types: ${record.query.types.join(", ")}`,
          `- A records: ${record.response.A.map(escapeInline).join(", ") || "None"}`,
          `- AAAA records: ${record.response.AAAA.map(escapeInline).join(", ") || "None"}`,
        ]
      : [
          `- TLS port: ${record.request.port}`,
          `- Connected address: ${escapeInline(record.request.connectedAddress)}`,
          `- Certificate present: ${record.response.certificatePresent}`,
          `- Authorized by local trust store: ${record.response.authorized}`,
          `- Protocol: ${escapeInline(record.response.protocol ?? "Unknown")}`,
          `- Subject: ${record.response.subject ? Object.entries(record.response.subject).map(([key, value]) => `${escapeInline(key)}=${escapeInline(value)}`).join(", ") : "Unavailable"}`,
          `- Issuer: ${record.response.issuer ? Object.entries(record.response.issuer).map(([key, value]) => `${escapeInline(key)}=${escapeInline(value)}`).join(", ") : "Unavailable"}`,
          `- Validity: ${escapeInline(record.response.validFrom ?? "Unknown")} to ${escapeInline(record.response.validTo ?? "Unknown")}`,
          `- SHA-256 fingerprint: ${escapeInline(record.response.fingerprint256 ?? "Unavailable")}`,
          `- Subject alternative names: ${record.response.subjectAltNames.map(escapeInline).join(", ") || "None"}`,
          ...(record.response.authorizationError ? [`- Trust error: ${escapeInline(record.response.authorizationError)}`] : []),
          ...(record.response.error ? [`- Handshake error: ${escapeInline(record.response.error)}`] : []),
        ];
    lines.push(
      `### ${escapeInline(record.activity)} — ${escapeInline(record.target)}`,
      "",
      `- ID: ${escapeInline(record.id)}`,
      `- Captured: ${escapeInline(record.capturedAt)}`,
      `- SHA-256: ${escapeInline(record.sha256)}`,
      "",
      ...activityDetails,
      "",
    );
  }
  lines.push("---", "Generated locally by Riftor. Findings reflect the evidence and review recorded in this engagement.", "");
  return lines.join("\n");
}

function escapeInline(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|<>~-]/g, "\\$&").replace(/[\r\n]+/g, " ");
}
