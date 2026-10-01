import { randomUUID } from "node:crypto";
import { open, readFile, rename, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { withFileLock } from "./file-lock.js";
import type { Finding, FindingConfidence, FindingSeverity, FindingStatus } from "./findings.js";
import { assertWorkspaceReady } from "./workspace-guard.js";

interface FindingState {
  version: 1;
  findings: Finding[];
}

const MAX_STATE_BYTES = 8 * 1024 * 1024;
const MAX_FINDINGS = 1_000;
const MAX_EVIDENCE_IDS = 100;
const MAX_ID_LENGTH = 128;
const MAX_TITLE_LENGTH = 256;
const MAX_TARGET_LENGTH = 2_048;
const MAX_DESCRIPTION_LENGTH = 20_000;
const MAX_REMEDIATION_LENGTH = 20_000;
const SEVERITIES = new Set<FindingSeverity>(["critical", "high", "medium", "low", "info"]);
const CONFIDENCES = new Set<FindingConfidence>(["confirmed", "high", "medium", "low"]);
const STATUSES = new Set<FindingStatus>(["open", "resolved", "accepted"]);

export class FindingStore {
  readonly #directory: string;
  readonly #path: string;
  readonly #lockPath: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#path = join(this.#directory, "findings.json");
    this.#lockPath = join(this.#directory, "findings.lock");
  }

  async list(): Promise<Finding[]> {
    return withFileLock(this.#lockPath, async () => cloneFindings(await this.#readUnlocked()));
  }

  async save(findings: Finding[]): Promise<void> {
    const validated = validateFindings(findings);
    await withFileLock(this.#lockPath, () => this.#writeUnlocked(validated));
  }

  /** Read, mutate, validate, and atomically persist findings while holding the process-shared lock. */
  async update(mutator: (findings: Finding[]) => Finding[] | void | Promise<Finding[] | void>): Promise<Finding[]> {
    return withFileLock(this.#lockPath, async () => {
      const current = await this.#readUnlocked();
      const draft = cloneFindings(current);
      const result = await mutator(draft);
      const validated = validateFindings(result === undefined ? draft : result);
      await this.#writeUnlocked(validated);
      return cloneFindings(validated);
    });
  }

  async #readUnlocked(): Promise<Finding[]> {
    await assertWorkspaceReady(dirname(this.#directory));
    let contents: string;
    try {
      const info = await stat(this.#path);
      if (info.size > MAX_STATE_BYTES) throw new Error(`Findings state exceeds ${MAX_STATE_BYTES} bytes`);
      contents = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
    if (Buffer.byteLength(contents, "utf8") > MAX_STATE_BYTES) {
      throw new Error(`Findings state exceeds ${MAX_STATE_BYTES} bytes`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(contents) as unknown;
    } catch {
      throw new Error("Malformed findings state: invalid JSON");
    }
    if (!isRecord(parsed) || parsed.version !== 1 || !Array.isArray(parsed.findings)) {
      throw new Error("Unsupported or malformed findings state");
    }
    return validateFindings(parsed.findings);
  }

  async #writeUnlocked(findings: Finding[]): Promise<void> {
    await assertWorkspaceReady(dirname(this.#directory));
    const state: FindingState = { version: 1, findings };
    const contents = `${JSON.stringify(state, null, 2)}\n`;
    if (Buffer.byteLength(contents, "utf8") > MAX_STATE_BYTES) {
      throw new Error(`Findings state exceeds ${MAX_STATE_BYTES} bytes`);
    }
    const temporaryPath = join(this.#directory, `.findings-${randomUUID()}.tmp`);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(temporaryPath, "wx", 0o600);
      await handle.writeFile(contents, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporaryPath, this.#path);
    } catch (error) {
      if (handle) await handle.close().catch(() => undefined);
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw error;
    }
  }
}

function validateFindings(value: unknown): Finding[] {
  if (!Array.isArray(value) || value.length > MAX_FINDINGS) {
    throw new Error(`Findings must be an array with at most ${MAX_FINDINGS} entries`);
  }
  const seenIds = new Set<string>();
  return value.map((entry, index) => {
    const context = `Finding at index ${index}`;
    if (!isRecord(entry)) throw new Error(`${context} must be an object`);
    const expectedKeys = ["id", "engagementId", "createdAt", "updatedAt", "title", "severity", "confidence", "status", "target", "description", "remediation", "evidenceIds"];
    if (Object.keys(entry).length !== expectedKeys.length || expectedKeys.some((key) => !Object.hasOwn(entry, key))) {
      throw new Error(`${context} has missing or unsupported fields`);
    }
    const id = boundedString(entry.id, `${context}.id`, MAX_ID_LENGTH);
    if (seenIds.has(id)) throw new Error(`Duplicate finding id: ${id}`);
    seenIds.add(id);
    const engagementId = boundedString(entry.engagementId, `${context}.engagementId`, MAX_ID_LENGTH);
    const createdAt = isoDate(entry.createdAt, `${context}.createdAt`);
    const updatedAt = isoDate(entry.updatedAt, `${context}.updatedAt`);
    if (Date.parse(updatedAt) < Date.parse(createdAt)) throw new Error(`${context}.updatedAt precedes createdAt`);
    const title = boundedString(entry.title, `${context}.title`, MAX_TITLE_LENGTH);
    const target = boundedString(entry.target, `${context}.target`, MAX_TARGET_LENGTH);
    const description = boundedString(entry.description, `${context}.description`, MAX_DESCRIPTION_LENGTH, true);
    const remediation = boundedString(entry.remediation, `${context}.remediation`, MAX_REMEDIATION_LENGTH, true);
    if (typeof entry.severity !== "string" || !SEVERITIES.has(entry.severity as FindingSeverity)) throw new Error(`${context}.severity is invalid`);
    if (typeof entry.confidence !== "string" || !CONFIDENCES.has(entry.confidence as FindingConfidence)) throw new Error(`${context}.confidence is invalid`);
    if (typeof entry.status !== "string" || !STATUSES.has(entry.status as FindingStatus)) throw new Error(`${context}.status is invalid`);
    if (!Array.isArray(entry.evidenceIds) || entry.evidenceIds.length > MAX_EVIDENCE_IDS) {
      throw new Error(`${context}.evidenceIds must contain at most ${MAX_EVIDENCE_IDS} entries`);
    }
    const evidenceIds = entry.evidenceIds.map((item, itemIndex) => boundedString(item, `${context}.evidenceIds[${itemIndex}]`, MAX_ID_LENGTH));
    if (new Set(evidenceIds).size !== evidenceIds.length) throw new Error(`${context}.evidenceIds contains duplicates`);
    return {
      id,
      engagementId,
      createdAt,
      updatedAt,
      title,
      severity: entry.severity as FindingSeverity,
      confidence: entry.confidence as FindingConfidence,
      status: entry.status as FindingStatus,
      target,
      description,
      remediation,
      evidenceIds,
    };
  });
}

function boundedString(value: unknown, field: string, maxLength: number, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.trim().length === 0) || value.length > maxLength || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    throw new Error(`${field} must be a valid string of at most ${maxLength} characters`);
  }
  return value;
}

function isoDate(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    throw new Error(`${field} must be an ISO UTC timestamp`);
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) throw new Error(`${field} is invalid`);
  return value;
}

function cloneFindings(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({ ...finding, evidenceIds: [...finding.evidenceIds] }));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
