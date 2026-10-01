import { randomUUID } from "node:crypto";
import { chmod, mkdir, open, rename, rm } from "node:fs/promises";
import { join } from "node:path";

export interface ActionBudgetConfig {
  targetCooldownMs: number;
  maxActions: number;
  windowMs: number;
}

interface Reservation {
  at: number;
  target: string;
  activity: string;
}

interface BudgetState {
  version: 1;
  reservations: Reservation[];
}

export const DEFAULT_ACTION_BUDGET: Readonly<ActionBudgetConfig> = Object.freeze({
  targetCooldownMs: 2_000,
  maxActions: 60,
  windowMs: 60_000,
});

const MAX_BUDGET_BYTES = 2 * 1024 * 1024;
const MAX_RESERVATIONS = 10_000;

/** Caller must hold the engagement store's cross-process action lock. */
export async function reserveActionBudget(
  workdir: string,
  target: string,
  activity: string,
  config: ActionBudgetConfig = DEFAULT_ACTION_BUDGET,
  now = Date.now(),
): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number; limit: "target_cooldown" | "workspace_window" }> {
  validateConfig(config);
  if (!Number.isSafeInteger(now) || now < 0 || !target || target.length > 2_048 || !activity || activity.length > 128) {
    throw new Error("Invalid action budget reservation");
  }
  const directory = join(workdir, ".riftor");
  const path = join(directory, "action-budget.json");
  const state = await readState(path, now);
  const fresh = state.reservations.filter((entry) => now - entry.at < config.windowMs);
  const prior = fresh.findLast((entry) => entry.target === target && entry.activity === activity);
  if (prior) {
    const remaining = config.targetCooldownMs - (now - prior.at);
    if (remaining > 0) return { allowed: false, retryAfterMs: remaining, limit: "target_cooldown" };
  }
  if (fresh.length >= config.maxActions) {
    const oldest = Math.min(...fresh.map((entry) => entry.at));
    return { allowed: false, retryAfterMs: Math.max(1, config.windowMs - (now - oldest)), limit: "workspace_window" };
  }

  fresh.push({ at: now, target, activity });
  if (fresh.length > MAX_RESERVATIONS) throw new Error("Action budget state exceeds the supported reservation count");
  const contents = `${JSON.stringify({ version: 1, reservations: fresh } satisfies BudgetState, null, 2)}\n`;
  if (Buffer.byteLength(contents, "utf8") > MAX_BUDGET_BYTES) throw new Error("Action budget state exceeds the supported size");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const temporaryPath = join(directory, `.action-budget-${randomUUID()}.tmp`);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, path);
    await chmod(path, 0o600);
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    throw error;
  }
  return { allowed: true };
}

async function readState(path: string, now: number): Promise<BudgetState> {
  let raw: string;
  try {
    raw = await readBoundedFile(path);
  } catch (error) {
    if (isMissing(error)) return { version: 1, reservations: [] };
    throw error;
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_BUDGET_BYTES) throw new Error("Action budget state exceeds the supported size");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error("Malformed action budget state JSON");
  }
  if (!isRecord(parsed) || Object.keys(parsed).length !== 2 || !Object.hasOwn(parsed, "version") || !Object.hasOwn(parsed, "reservations") ||
    parsed.version !== 1 || !Array.isArray(parsed.reservations) || parsed.reservations.length > MAX_RESERVATIONS) {
    throw new Error("Unsupported or malformed action budget state");
  }
  const reservations = parsed.reservations.map((entry) => {
    if (!isRecord(entry) || Object.keys(entry).length !== 3 || !Object.hasOwn(entry, "at") || !Object.hasOwn(entry, "target") || !Object.hasOwn(entry, "activity") ||
      !Number.isSafeInteger(entry.at) || (entry.at as number) > now + 60_000 || (entry.at as number) < 0 ||
      typeof entry.target !== "string" || !entry.target || entry.target.length > 2_048 ||
      typeof entry.activity !== "string" || !entry.activity || entry.activity.length > 128) {
      throw new Error("Malformed action budget reservation");
    }
    return { at: entry.at as number, target: entry.target, activity: entry.activity };
  });
  return { version: 1, reservations };
}

async function readBoundedFile(path: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > MAX_BUDGET_BYTES) throw new Error("Action budget state exceeds the supported size");
    const chunks: Buffer[] = [];
    let length = 0;
    while (length <= MAX_BUDGET_BYTES) {
      const chunk = Buffer.alloc(Math.min(64 * 1024, MAX_BUDGET_BYTES + 1 - length));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, length);
      if (!bytesRead) break;
      length += bytesRead;
      chunks.push(chunk.subarray(0, bytesRead));
    }
    if (length > MAX_BUDGET_BYTES) throw new Error("Action budget state exceeds the supported size");
    return Buffer.concat(chunks, length).toString("utf8");
  } finally {
    await handle.close();
  }
}

function validateConfig(config: ActionBudgetConfig): void {
  if (!Number.isSafeInteger(config.targetCooldownMs) || config.targetCooldownMs < 0 || config.targetCooldownMs > 60 * 60_000 ||
    !Number.isSafeInteger(config.maxActions) || config.maxActions < 1 || config.maxActions > MAX_RESERVATIONS ||
    !Number.isSafeInteger(config.windowMs) || config.windowMs < 1 || config.windowMs > 24 * 60 * 60_000) {
    throw new Error("Invalid action budget configuration");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
