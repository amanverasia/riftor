import { open, mkdir, chmod, readFile, rm, stat } from "node:fs/promises";
import { dirname } from "node:path";

const LOCK_TIMEOUT_MS = 30_000;
const STALE_LOCK_MS = 120_000;

export async function acquireFileLock(path: string): Promise<() => Promise<void>> {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const deadline = Date.now() + LOCK_TIMEOUT_MS;

  while (Date.now() < deadline) {
    try {
      const handle = await open(path, "wx", 0o600);
      try {
        await handle.writeFile(JSON.stringify({ pid: process.pid, createdAt: Date.now() }));
      } catch (error) {
        await rm(path, { force: true });
        throw error;
      } finally {
        await handle.close();
      }
      return async () => {
        await rm(path, { force: true });
      };
    } catch (error) {
      if (!isExists(error)) throw error;
      if (await isAbandoned(path)) {
        await rm(path, { force: true });
        continue;
      }
      await delay(50);
    }
  }
  throw new Error(`Timed out waiting for Riftor lock: ${path}`);
}

export async function withFileLock<T>(path: string, action: () => Promise<T>): Promise<T> {
  const release = await acquireFileLock(path);
  try {
    return await action();
  } finally {
    await release();
  }
}

async function isAbandoned(path: string): Promise<boolean> {
  let lock: { pid?: number; createdAt?: number } = {};
  let modifiedAt: number;
  try {
    lock = JSON.parse(await readFile(path, "utf8")) as typeof lock;
    modifiedAt = (await stat(path)).mtimeMs;
  } catch (error) {
    if (isMissing(error)) return true;
    try {
      return Date.now() - (await stat(path)).mtimeMs >= STALE_LOCK_MS;
    } catch {
      return false;
    }
  }
  const age = Date.now() - (lock.createdAt ?? modifiedAt);
  if (age < STALE_LOCK_MS) return false;
  if (!Number.isInteger(lock.pid) || (lock.pid ?? 0) < 1) return true;
  try {
    process.kill(lock.pid!, 0);
    return false;
  } catch (error) {
    return typeof error === "object" && error !== null && "code" in error && error.code === "ESRCH";
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isExists(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "EEXIST";
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
