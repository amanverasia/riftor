import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { acquireFileLock } from "./file-lock.js";
import type { Engagement } from "./types.js";
import { normalizeScopeRule } from "../security/scope.js";

interface StoredState {
  version: 2;
  activeEngagementId: string | null;
  engagements: Engagement[];
}

export class EngagementStore {
  readonly #directory: string;
  readonly #statePath: string;
  readonly #auditPath: string;
  readonly #actionLockPath: string;

  constructor(workdir: string) {
    this.#directory = join(workdir, ".riftor");
    this.#statePath = join(this.#directory, "engagement.json");
    this.#auditPath = join(this.#directory, "audit.jsonl");
    this.#actionLockPath = join(this.#directory, "action.lock");
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
    const release = await this.acquireActionLock();
    try {
      const state = await this.#readState();
      if (!state.engagements.some((item) => item.id === id)) return false;
      state.activeEngagementId = id;
      await this.#writeState(state);
      return true;
    } finally {
      await release();
    }
  }

  async save(engagement: Engagement | null): Promise<void> {
    const release = await this.acquireActionLock();
    try {
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
    } finally {
      await release();
    }
  }

  /**
   * Atomically update the active engagement while holding the same lock used by
   * saves and actions. The mutator receives a detached working copy; it may
   * mutate that copy or return a replacement. Returning a value detached from
   * the store prevents callers from changing persisted state without a save.
   */
  async updateActive(
    mutator: (engagement: Engagement) => Engagement | void | Promise<Engagement | void>,
    expectedEngagementId?: string,
  ): Promise<Engagement | null> {
    const release = await this.acquireActionLock();
    try {
      const state = await this.#readState();
      if (state.activeEngagementId === null) return null;
      if (expectedEngagementId !== undefined && state.activeEngagementId !== expectedEngagementId) return null;

      const index = state.engagements.findIndex((item) => item.id === state.activeEngagementId);
      if (index === -1) throw new Error("Active engagement ID does not exist in state");

      const originalId = state.engagements[index].id;
      const workingCopy = structuredClone(state.engagements[index]);
      const result = await mutator(workingCopy);
      const updated = validateEngagement(result === undefined ? workingCopy : result);
      if (updated.id !== originalId) throw new Error("An active engagement ID cannot be changed");

      state.engagements[index] = structuredClone(updated);
      await this.#writeState(state);
      return structuredClone(updated);
    } finally {
      await release();
    }
  }

  acquireActionLock(): Promise<() => Promise<void>> {
    return acquireFileLock(this.#actionLockPath);
  }

  async #readState(): Promise<StoredState> {
    try {
      const raw = await readFile(this.#statePath, "utf8");
      const stored: unknown = JSON.parse(raw);
      if (!isRecord(stored)) throw new Error("Malformed engagement state");
      if (stored.version === 1 && "engagement" in stored) {
        const engagement = stored.engagement === null ? null : validateEngagement(stored.engagement);
        const engagements = engagement ? [engagement] : [];
        return { version: 2, activeEngagementId: engagement?.id ?? null, engagements };
      }
      if (stored.version !== 2 || !Array.isArray(stored.engagements) ||
        !(stored.activeEngagementId === null || typeof stored.activeEngagementId === "string")) {
        throw new Error("Unsupported or malformed engagement state");
      }
      const engagements = stored.engagements.map(validateEngagement);
      const ids = engagements.map((item) => item.id);
      if (new Set(ids).size !== ids.length) throw new Error("Duplicate engagement IDs in state");
      if (stored.activeEngagementId !== null && !ids.includes(stored.activeEngagementId)) {
        throw new Error("Active engagement ID does not exist in state");
      }
      return { version: 2, activeEngagementId: stored.activeEngagementId, engagements };
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

function validateEngagement(value: unknown): Engagement {
  if (!isRecord(value) || !isRecord(value.authorization) || !isRecord(value.scope)) {
    throw new Error("Malformed engagement record");
  }
  const { id, name, createdAt, authorization, scope } = value;
  const authStrings = [authorization.reference, authorization.authorizedBy, authorization.startsAt, authorization.expiresAt];
  if (typeof id !== "string" || !id || typeof name !== "string" || !name || typeof createdAt !== "string" ||
    !Number.isFinite(Date.parse(createdAt)) || !authStrings.every((item) => typeof item === "string" && item.length > 0) ||
    !Number.isFinite(Date.parse(authorization.startsAt as string)) || !Number.isFinite(Date.parse(authorization.expiresAt as string)) ||
    Date.parse(authorization.expiresAt as string) <= Date.parse(authorization.startsAt as string) ||
    !Array.isArray(authorization.activities) || authorization.activities.length === 0 || authorization.activities.length > 32 ||
    !authorization.activities.every((item) => typeof item === "string" && item.length > 0) ||
    !Array.isArray(scope.include) || !Array.isArray(scope.exclude) || scope.include.length > 10_000 || scope.exclude.length > 10_000 ||
    !scope.include.every(validScopeRule) || !scope.exclude.every(validScopeRule)) {
    throw new Error(`Malformed engagement record: ${String(id ?? "unknown")}`);
  }
  return value as unknown as Engagement;
}

function validScopeRule(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    return normalizeScopeRule(value) === value;
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
