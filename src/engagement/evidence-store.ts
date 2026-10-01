import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { HttpHeadersEvidence } from "./evidence.js";

type EvidenceDraft = Omit<HttpHeadersEvidence, "id" | "capturedAt" | "previousSha256" | "sha256">;

export class EvidenceStore {
  readonly #directory: string;
  readonly #path: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#path = join(this.#directory, "evidence.jsonl");
  }

  async append(draft: EvidenceDraft): Promise<HttpHeadersEvidence> {
    await this.#prepareDirectory();
    const previous = await this.list();
    const payload = {
      id: randomUUID(),
      ...draft,
      capturedAt: new Date().toISOString(),
      previousSha256: previous.at(-1)?.sha256 ?? null,
    };
    const record: HttpHeadersEvidence = { ...payload, sha256: hash(payload) };
    const handle = await open(this.#path, "a", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`);
    } finally {
      await handle.close();
    }
    await chmod(this.#path, 0o600);
    return record;
  }

  async list(): Promise<HttpHeadersEvidence[]> {
    let raw: string;
    try {
      raw = await readFile(this.#path, "utf8");
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
    let previousSha256: string | null = null;
    return raw.split("\n").filter(Boolean).map((line, index) => {
      const record = JSON.parse(line) as HttpHeadersEvidence;
      const { sha256, ...payload } = record;
      if (record.previousSha256 !== previousSha256 || typeof sha256 !== "string" || hash(payload) !== sha256) {
        throw new Error(`Evidence integrity check failed on record ${index + 1}`);
      }
      previousSha256 = sha256;
      return record;
    });
  }

  async #prepareDirectory(): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
  }
}

function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
