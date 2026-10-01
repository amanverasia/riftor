import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { Engagement } from "./types.js";

interface StoredState {
  version: 2;
  activeEngagementId: string | null;
  engagements: Engagement[];
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
    const state = await this.#readState();
    return state.engagements.find((item) => item.id === state.activeEngagementId) ?? null;
  }

  async list(): Promise<Engagement[]> {
    const state = await this.#readState();
    return state.engagements;
  }

  async activate(id: string): Promise<boolean> {
    const state = await this.#readState();
    if (!state.engagements.some((item) => item.id === id)) return false;
    state.activeEngagementId = id;
    await this.#writeState(state);
    return true;
  }

  async save(engagement: Engagement | null): Promise<void> {
    const state = await this.#readState();
    if (engagement === null) {
      state.activeEngagementId = null;
    } else {
      const index = state.engagements.findIndex((item) => item.id === engagement.id);
      if (index === -1) state.engagements.push(engagement);
      else state.engagements[index] = engagement;
      state.activeEngagementId = engagement.id;
    }
    await this.#writeState(state);
  }

  async #readState(): Promise<StoredState> {
    try {
      const raw = await readFile(this.#statePath, "utf8");
      const stored = JSON.parse(raw) as { version?: number; engagement?: Engagement | null; activeEngagementId?: string | null; engagements?: Engagement[] };
      if (stored.version === 1 && "engagement" in stored) {
        const engagements = stored.engagement ? [stored.engagement] : [];
        return { version: 2, activeEngagementId: stored.engagement?.id ?? null, engagements };
      }
      if (stored.version !== 2 || !Array.isArray(stored.engagements) ||
        (stored.activeEngagementId !== null && !stored.engagements.some((item) => item.id === stored.activeEngagementId))) {
        throw new Error("Unsupported or malformed engagement state");
      }
      return { version: 2, activeEngagementId: stored.activeEngagementId ?? null, engagements: stored.engagements };
    } catch (error) {
      if (isMissing(error)) return { version: 2, activeEngagementId: null, engagements: [] };
      throw error;
    }
  }

  async #writeState(state: StoredState): Promise<void> {
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
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
