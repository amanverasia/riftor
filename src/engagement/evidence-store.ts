import { createHash, randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { chmod, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { withFileLock } from "./file-lock.js";
import type { DnsLookupEvidence, EvidenceRecord, HttpHeadersEvidence, TlsCertificateEvidence } from "./evidence.js";
import { assertWorkspaceReady } from "./workspace-guard.js";

type EvidenceDraft =
  | Omit<HttpHeadersEvidence, "id" | "capturedAt" | "previousSha256" | "sha256">
  | Omit<DnsLookupEvidence, "id" | "capturedAt" | "previousSha256" | "sha256">
  | Omit<TlsCertificateEvidence, "id" | "capturedAt" | "previousSha256" | "sha256">;

export class EvidenceStore {
  readonly #directory: string;
  readonly #path: string;
  readonly #lockPath: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#path = join(this.#directory, "evidence.jsonl");
    this.#lockPath = join(this.#directory, "evidence.lock");
  }

  async append(draft: EvidenceDraft): Promise<EvidenceRecord> {
    return withFileLock(this.#lockPath, async () => {
      await this.#prepareDirectory();
      const previous = await this.#readRecords();
      const payload = {
        id: randomUUID(),
        ...draft,
        capturedAt: new Date().toISOString(),
        previousSha256: previous.at(-1)?.sha256 ?? null,
      };
      const record: EvidenceRecord = { ...payload, sha256: hash(payload) };
      const handle = await open(this.#path, "a", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(record)}\n`);
      } finally {
        await handle.close();
      }
      await chmod(this.#path, 0o600);
      return record;
    });
  }

  async list(): Promise<EvidenceRecord[]> {
    return withFileLock(this.#lockPath, () => this.#readRecords());
  }

  async replaceAll(records: EvidenceRecord[]): Promise<void> {
    const validated = validateEvidenceRecords(records);
    const contents = validated.map((record) => JSON.stringify(record)).join("\n") + (validated.length ? "\n" : "");
    if (Buffer.byteLength(contents, "utf8") > MAX_EVIDENCE_BYTES) throw new Error("Evidence import exceeds the maximum supported size");
    return withFileLock(this.#lockPath, async () => {
      await assertWorkspaceReady(dirname(this.#directory));
      await this.#prepareDirectory();
      const temporaryPath = join(this.#directory, `.evidence-${randomUUID()}.tmp`);
      try {
        await writeFile(temporaryPath, contents, { mode: 0o600, flag: "wx" });
        await rename(temporaryPath, this.#path);
        await chmod(this.#path, 0o600);
      } catch (error) {
        await rm(temporaryPath, { force: true }).catch(() => undefined);
        throw error;
      }
    });
  }

  async #readRecords(): Promise<EvidenceRecord[]> {
    await assertWorkspaceReady(dirname(this.#directory));
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
    if (Buffer.byteLength(raw, "utf8") > MAX_EVIDENCE_BYTES) throw new Error("Evidence file exceeds the maximum supported size");
    const records = raw.split("\n").filter(Boolean).map((line, index) => {
      try {
        return JSON.parse(line) as unknown;
      } catch {
        throw new Error(`Evidence integrity check failed on record ${index + 1}: invalid JSON`);
      }
    });
    return validateEvidenceRecords(records);
  }

  async #prepareDirectory(): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
  }
}

const MAX_EVIDENCE_BYTES = 50 * 1024 * 1024;
const MAX_EVIDENCE_RECORDS = 100_000;

function validateEvidenceRecords(value: unknown): EvidenceRecord[] {
  if (!Array.isArray(value) || value.length > MAX_EVIDENCE_RECORDS) throw new Error("Evidence must be an array with a supported number of records");
  let previousSha256: string | null = null;
  return value.map((entry, index) => {
    if (!isRecord(entry)) throw new Error(`Evidence integrity check failed on record ${index + 1}: malformed record`);
    const { sha256, ...payload } = entry;
    if (typeof entry.id !== "string" || !entry.id || entry.id.length > 128 ||
      typeof entry.engagementId !== "string" || !entry.engagementId || entry.engagementId.length > 128 ||
      typeof entry.target !== "string" || !entry.target || entry.target.length > 2_048 ||
      typeof entry.capturedAt !== "string" || !Number.isFinite(Date.parse(entry.capturedAt)) ||
      (entry.previousSha256 !== null && (typeof entry.previousSha256 !== "string" || !/^[a-f\d]{64}$/i.test(entry.previousSha256))) ||
      typeof sha256 !== "string" || !/^[a-f\d]{64}$/i.test(sha256) ||
      entry.previousSha256 !== previousSha256 || hash(payload) !== sha256) {
      throw new Error(`Evidence integrity check failed on record ${index + 1}`);
    }
    validateActivity(entry, index);
    previousSha256 = sha256;
    return entry as unknown as EvidenceRecord;
  });
}

function validateActivity(record: Record<string, unknown>, index: number): void {
  const label = `Evidence integrity check failed on record ${index + 1}`;
  if (record.activity === "dns_lookup") {
    const response = isRecord(record.response) ? record.response : null;
    if (!exactKeys(record, ["id", "engagementId", "target", "capturedAt", "previousSha256", "sha256", "activity", "query", "response"]) ||
      !isRecord(record.query) || !exactKeys(record.query, ["types"]) || !Array.isArray(record.query.types) || record.query.types.length !== 2 ||
      record.query.types[0] !== "A" || record.query.types[1] !== "AAAA" || !response ||
      !exactKeys(response, ["A", "AAAA"]) ||
      !Array.isArray(response.A) || response.A.length > 256 || !response.A.every((address) => isIp(address) && address.includes(".")) ||
      !Array.isArray(response.AAAA) || response.AAAA.length > 256 || !response.AAAA.every((address) => isIp(address) && address.includes(":"))) {
      throw new Error(`Evidence integrity check failed on record ${index + 1}: malformed DNS observation`);
    }
    return;
  }
  const request = isRecord(record.request) ? record.request : null;
  const response = isRecord(record.response) ? record.response : null;
  if (!request || !response) throw new Error(`Evidence integrity check failed on record ${index + 1}: missing request or response`);

  if (record.activity === "http_headers") {
    const legacy = request.connectedAddress === undefined && request.resolvedAddresses === undefined;
    if (!exactKeys(record, ["id", "engagementId", "target", "capturedAt", "previousSha256", "sha256", "activity", "request", "response"]) ||
      !(legacy ? exactKeys(request, ["method", "url"]) : exactKeys(request, ["method", "url", "resolvedAddresses", "connectedAddress"])) ||
      !exactKeys(response, ["status", "statusText", "headers"]) || request.method !== "HEAD" || typeof request.url !== "string" || request.url.length > 4_096 ||
      !validWebUrl(request.url) || (!legacy && (!isIp(request.connectedAddress) || !Array.isArray(request.resolvedAddresses) ||
      request.resolvedAddresses.length === 0 || request.resolvedAddresses.length > 256 ||
      !request.resolvedAddresses.every(isIp) || !request.resolvedAddresses.includes(request.connectedAddress as string))) ||
      !Number.isInteger(response.status) || (response.status as number) < 0 || (response.status as number) > 599 ||
      typeof response.statusText !== "string" || response.statusText.length > 300 || !isRecord(response.headers) ||
      Object.keys(response.headers).length > 20 || !Object.entries(response.headers).every(([key, value]) => key.length <= 100 && typeof value === "string" && value.length <= 500)) {
      throw new Error(`Evidence integrity check failed on record ${index + 1}: malformed HTTP observation`);
    }
    return;
  }

  if (record.activity === "tls_certificate") {
    const tlsResponseKeys = ["certificatePresent", "subject", "issuer", "validFrom", "validTo", "fingerprint256", "subjectAltNames", "protocol", "authorized", "authorizationError"];
    if (!exactKeys(record, ["id", "engagementId", "target", "capturedAt", "previousSha256", "sha256", "activity", "request", "response"]) ||
      !exactKeys(request, ["protocol", "port", "serverName", "connectedAddress"]) ||
      !(exactKeys(response, tlsResponseKeys) || exactKeys(response, [...tlsResponseKeys, "error"])) ||
      request.protocol !== "TLS" || request.port !== 443 || typeof request.serverName !== "string" || request.serverName.length > 253 ||
      !isIp(request.connectedAddress) || typeof response.certificatePresent !== "boolean" ||
      !(response.subject === null || isStringRecord(response.subject)) || !(response.issuer === null || isStringRecord(response.issuer)) ||
      !nullableString(response.validFrom, 100) || !nullableString(response.validTo, 100) ||
      !nullableString(response.fingerprint256, 100) || !Array.isArray(response.subjectAltNames) || response.subjectAltNames.length > 50 ||
      !response.subjectAltNames.every((name) => typeof name === "string" && name.length <= 300) ||
      !nullableString(response.protocol, 30) || typeof response.authorized !== "boolean" ||
      !nullableString(response.authorizationError, 300) || !(response.error === undefined || typeof response.error === "string" && response.error.length <= 300)) {
      throw new Error(`Evidence integrity check failed on record ${index + 1}: malformed TLS observation`);
    }
    return;
  }
  throw new Error(`Evidence integrity check failed on record ${index + 1}: unsupported activity`);
}

function validWebUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isIp(value: unknown): value is string {
  return typeof value === "string" && isIP(value) !== 0;
}

function nullableString(value: unknown, maxLength: number): boolean {
  return value === null || typeof value === "string" && value.length <= maxLength;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  return isRecord(value) && Object.keys(value).length <= 20 && Object.entries(value).every(([key, item]) => key.length <= 80 && typeof item === "string" && item.length <= 300);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}


function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
