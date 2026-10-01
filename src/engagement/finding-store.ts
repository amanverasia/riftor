import { randomUUID } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Finding } from "./findings.js";

interface FindingState {
  version: 1;
  findings: Finding[];
}

export class FindingStore {
  readonly #directory: string;
  readonly #path: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#path = join(this.#directory, "findings.json");
  }

  async list(): Promise<Finding[]> {
    try {
      const state = JSON.parse(await readFile(this.#path, "utf8")) as FindingState;
      if (state.version !== 1 || !Array.isArray(state.findings)) {
        throw new Error("Unsupported or malformed findings state");
      }
      return state.findings;
    } catch (error) {
      if (isMissing(error)) return [];
      throw error;
    }
  }

  async save(findings: Finding[]): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
    const temporaryPath = join(this.#directory, `.findings-${randomUUID()}.tmp`);
    const state: FindingState = { version: 1, findings };
    await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.#path);
    await chmod(this.#path, 0o600);
  }
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
