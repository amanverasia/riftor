import { access } from "node:fs/promises";
import { join } from "node:path";

/** Prevent cooperating Riftor processes from observing a workspace mid-import. */
export async function assertWorkspaceReady(workdir: string): Promise<void> {
  try {
    await access(join(workdir, ".riftor-importing"));
  } catch (error) {
    if (isMissing(error)) return;
    throw error;
  }
  throw new Error("Riftor workspace import is in progress; retry after it finishes");
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
