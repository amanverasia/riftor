import { createHash } from "node:crypto";
import type { Finding } from "./findings.js";
import { normalizeTarget } from "../security/scope.js";

/** Stable, exact identity used to suggest duplicate findings within an engagement. */
export function findingIdentity(finding: Pick<Finding, "engagementId" | "target" | "title">): string {
  const target = normalizeTarget(finding.target);
  const title = finding.title.normalize("NFC").trim().replace(/\s+/gu, " ").toLowerCase();
  if (!title) throw new Error("Finding title cannot be empty");
  return JSON.stringify([finding.engagementId, target, title]);
}

/** Stable SARIF identity aligned with finding deduplication; severity can change without changing identity. */
export function findingFingerprint(finding: Pick<Finding, "engagementId" | "target" | "title">): string {
  let identity: string;
  try {
    identity = findingIdentity(finding);
  } catch {
    // Preserve reportability for older imported records whose target strings
    // predate strict target normalization. Such records are never deduped.
    const title = finding.title.normalize("NFC").trim().replace(/\s+/gu, " ").toLowerCase();
    identity = JSON.stringify([finding.engagementId, finding.target.trim().toLowerCase(), title]);
  }
  return createHash("sha256").update(identity).digest("hex");
}

/** Preserve the fingerprint shipped before stable finding identity was added. */
export function legacyFindingFingerprint(finding: Pick<Finding, "target" | "title" | "severity">): string {
  let target: string;
  try {
    target = normalizeTarget(finding.target);
  } catch {
    target = finding.target.trim().toLowerCase();
  }
  const identity = JSON.stringify([target, finding.severity, finding.title.trim().toLowerCase()]);
  return createHash("sha256").update(identity).digest("hex");
}
