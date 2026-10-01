import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, open, rename, rm, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import type { EvidenceRecord } from "./evidence.js";
import { EvidenceStore } from "./evidence-store.js";
import type { Finding } from "./findings.js";
import { FindingStore } from "./finding-store.js";
import type { Engagement } from "./types.js";
import { EngagementStore } from "./store.js";

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;

interface WorkspaceArchive {
  format: "riftor-workspace";
  version: 1;
  exportedAt: string;
  activeEngagementId: string | null;
  engagements: Engagement[];
  evidence: EvidenceRecord[];
  findings: Finding[];
  sha256: string;
}

export async function exportWorkspace(workdir: string, outputPath: string): Promise<string> {
  const engagementsStore = new EngagementStore(workdir);
  const evidenceStore = new EvidenceStore(workdir);
  const findingStore = new FindingStore(workdir);
  const [engagements, active, evidence, findings] = await Promise.all([
    engagementsStore.list(), engagementsStore.load(), evidenceStore.list(), findingStore.list(),
  ]);
  validateReferences(engagements, evidence, findings);
  const payload = {
    format: "riftor-workspace" as const,
    version: 1 as const,
    exportedAt: new Date().toISOString(),
    activeEngagementId: active?.id ?? null,
    engagements,
    evidence,
    findings,
  };
  const archive: WorkspaceArchive = { ...payload, sha256: digest(payload) };
  const contents = `${JSON.stringify(archive, null, 2)}\n`;
  if (Buffer.byteLength(contents, "utf8") > MAX_ARCHIVE_BYTES) throw new Error("Workspace archive exceeds the maximum supported size");
  const destination = resolve(outputPath);
  await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
  const handle = await open(destination, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
  } catch (error) {
    await rm(destination, { force: true }).catch(() => undefined);
    throw error;
  } finally {
    await handle.close();
  }
  return destination;
}

export async function importWorkspace(workdir: string, inputPath: string): Promise<{ engagements: number; evidence: number; findings: number }> {
  const source = resolve(inputPath);
  const raw = await readBoundedFile(source);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Workspace archive is not valid JSON");
  }
  const archive = validateArchive(parsed);
  const targetDirectory = join(resolve(workdir), ".riftor");
  try {
    await stat(targetDirectory);
    throw new Error("Import requires a workspace with no existing .riftor directory");
  } catch (error) {
    if (!isMissing(error)) throw error;
  }

  const stagingWorkdir = join(resolve(workdir), `.${basename(targetDirectory)}-import-${randomUUID()}`);
  await mkdir(stagingWorkdir, { mode: 0o700 });
  let targetCreated = false;
  const workspaceMarker = join(resolve(workdir), ".riftor-importing");
  let markerCreated = false;
  try {
    await new EngagementStore(stagingWorkdir).importInactive(archive.engagements);
    await new EvidenceStore(stagingWorkdir).replaceAll(archive.evidence);
    await new FindingStore(stagingWorkdir).save(archive.findings);
    const stagedEngagements = await new EngagementStore(stagingWorkdir).list();
    const stagedEvidence = await new EvidenceStore(stagingWorkdir).list();
    const stagedFindings = await new FindingStore(stagingWorkdir).list();
    validateReferences(stagedEngagements, stagedEvidence, stagedFindings);
    // Fence cooperating Riftor processes before reserving the destination.
    const markerHandle = await open(workspaceMarker, "wx", 0o600);
    await markerHandle.close();
    markerCreated = true;
    // mkdir is the no-replace reservation: unlike rename, it cannot overwrite
    // an empty .riftor directory created by another process in the meantime.
    await mkdir(targetDirectory, { mode: 0o700 });
    targetCreated = true;
    for (const name of ["engagement.json", "evidence.jsonl", "findings.json"]) {
      await rename(join(stagingWorkdir, ".riftor", name), join(targetDirectory, name));
    }
    await chmod(targetDirectory, 0o700);
    await rm(workspaceMarker);
    markerCreated = false;
    targetCreated = false;
    await rm(stagingWorkdir, { recursive: true, force: true });
    return { engagements: archive.engagements.length, evidence: archive.evidence.length, findings: archive.findings.length };
  } catch (error) {
    await rm(stagingWorkdir, { recursive: true, force: true }).catch(() => undefined);
    if (targetCreated) await rm(targetDirectory, { recursive: true, force: true }).catch(() => undefined);
    if (markerCreated) await rm(workspaceMarker, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function readBoundedFile(path: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_ARCHIVE_BYTES) throw new Error("Workspace archive is not a supported regular file");
    const chunks: Buffer[] = [];
    let length = 0;
    while (length <= MAX_ARCHIVE_BYTES) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, MAX_ARCHIVE_BYTES + 1 - length));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
      chunks.push(chunk.subarray(0, bytesRead));
    }
    if (length > MAX_ARCHIVE_BYTES) throw new Error("Workspace archive exceeds the maximum supported size");
    return Buffer.concat(chunks, length).toString("utf8");
  } finally {
    await handle.close();
  }
}

function validateArchive(value: unknown): WorkspaceArchive {
  if (!isRecord(value) || value.format !== "riftor-workspace" || value.version !== 1 ||
    typeof value.exportedAt !== "string" || !Number.isFinite(Date.parse(value.exportedAt)) ||
    !(value.activeEngagementId === null || typeof value.activeEngagementId === "string") ||
    !Array.isArray(value.engagements) || !Array.isArray(value.evidence) || !Array.isArray(value.findings) ||
    typeof value.sha256 !== "string" || !/^[a-f\d]{64}$/i.test(value.sha256)) {
    throw new Error("Unsupported or malformed Riftor workspace archive");
  }
  const { sha256, ...payload } = value;
  const actual = digest(payload);
  const expectedBytes = Buffer.from(sha256, "hex");
  const actualBytes = Buffer.from(actual, "hex");
  if (expectedBytes.length !== actualBytes.length || !timingSafeEqual(expectedBytes, actualBytes)) {
    throw new Error("Workspace archive SHA-256 integrity check failed");
  }
  const engagements = value.engagements as Engagement[];
  const evidence = value.evidence as EvidenceRecord[];
  const findings = value.findings as Finding[];
  validateReferences(engagements, evidence, findings);
  if (value.activeEngagementId !== null && !engagements.some((engagement) => engagement.id === value.activeEngagementId)) {
    throw new Error("Archive active engagement reference is invalid");
  }
  return value as unknown as WorkspaceArchive;
}

function validateReferences(engagements: Engagement[], evidence: EvidenceRecord[], findings: Finding[]): void {
  const engagementIds = new Set(engagements.map((engagement) => engagement.id));
  if (engagementIds.size !== engagements.length) throw new Error("Workspace has duplicate engagement IDs");
  const evidenceIds = new Set<string>();
  for (const record of evidence) {
    if (!engagementIds.has(record.engagementId)) throw new Error(`Evidence ${record.id} references a missing engagement`);
    if (evidenceIds.has(record.id)) throw new Error(`Workspace has duplicate evidence ID ${record.id}`);
    evidenceIds.add(record.id);
  }
  const findingIds = new Set<string>();
  for (const finding of findings) {
    if (!engagementIds.has(finding.engagementId)) throw new Error(`Finding ${finding.id} references a missing engagement`);
    if (findingIds.has(finding.id)) throw new Error(`Workspace has duplicate finding ID ${finding.id}`);
    findingIds.add(finding.id);
    for (const evidenceId of finding.evidenceIds) {
      if (!evidenceIds.has(evidenceId)) throw new Error(`Finding ${finding.id} references missing evidence ${evidenceId}`);
    }
  }
}

function digest(value: unknown): string {
  return createHash("sha256").update(canonicalize(value)).digest("hex");
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
