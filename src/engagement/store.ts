import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Engagement } from "./types.js";

interface StoredState {
  version: 1;
  engagement: Engagement | null;
}

export class EngagementStore {
  readonly #directory: string;
  readonly #statePath: string;
  readonly #auditPath: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#statePath = join(this.#directory, "engagement.json");
    this.#auditPath = join(this.#directory, "audit.jsonl");
  }

  async load(): Promise<Engagement | null> {
    try {
      const raw = await readFile(this.#statePath, "utf8");
      const state = JSON.parse(raw) as StoredState;
      if (state.version !== 1 || !("engagement" in state)) {
        throw new Error("Unsupported or malformed engagement state");
      }
      return state.engagement;
    } catch (error) {
      if (isMissing(error)) return null;
      throw error;
    }
  }

  async save(engagement: Engagement | null): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
    const state: StoredState = { version: 1, engagement };
    const temporaryPath = join(this.#directory, `.engagement-${randomUUID()}.tmp`);
    await writeFile(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
    await rename(temporaryPath, this.#statePath);
    await chmod(this.#statePath, 0o600);
  }

  async appendAudit(event: Record<string, unknown>): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
    const handle = await open(this.#auditPath, "a", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);
    } finally {
      await handle.close();
    }
    await chmod(this.#auditPath, 0o600);
  }
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
