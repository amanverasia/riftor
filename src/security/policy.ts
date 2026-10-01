import type { Engagement, PolicyDecision } from "../engagement/types.js";
import { isTargetInScope, normalizeScopeRule, normalizeTarget } from "./scope.js";

export interface ActionRequest {
  target: string;
  activity: string;
  now?: Date;
  humanApproved?: boolean;
  approvalAvailable?: boolean;
}

export function evaluateAction(
  engagement: Engagement | null,
  request: ActionRequest,
): PolicyDecision {
  if (!engagement) return { outcome: "deny", reason: "No active engagement" };

  if (!engagement.authorization || !Array.isArray(engagement.authorization.activities) ||
    !engagement.authorization.activities.every((activity) => typeof activity === "string")) {
    return { outcome: "deny", reason: "Authorized activity data is malformed" };
  }
  if (!engagement.scope || !Array.isArray(engagement.scope.include) || !Array.isArray(engagement.scope.exclude)) {
    return { outcome: "deny", reason: "Engagement scope is malformed" };
  }
  if (!engagement.scope.include.every(isNormalizedRule) || !engagement.scope.exclude.every(isNormalizedRule)) {
    return { outcome: "deny", reason: "Engagement scope rules are malformed" };
  }

  const startsAt = Date.parse(engagement.authorization.startsAt);
  const expiresAt = Date.parse(engagement.authorization.expiresAt);
  const now = (request.now ?? new Date()).getTime();
  if (!Number.isFinite(startsAt) || !Number.isFinite(expiresAt)) {
    return { outcome: "deny", reason: "Authorization dates are invalid" };
  }
  if (now < startsAt) return { outcome: "deny", reason: "Authorization has not started" };
  if (now >= expiresAt) return { outcome: "deny", reason: "Authorization has expired" };

  let target: string;
  try {
    target = normalizeTarget(request.target);
  } catch {
    return { outcome: "deny", reason: "Target is malformed" };
  }
  if (!isTargetInScope(target, engagement.scope.include, engagement.scope.exclude)) {
    return { outcome: "deny", reason: "Target is outside engagement scope" };
  }

  if (!engagement.authorization.activities.some((activity) => activity === request.activity)) {
    return { outcome: "deny", reason: `Activity is not authorized: ${request.activity}` };
  }

  if (request.humanApproved) return { outcome: "allow", reason: "Approved by operator" };
  if (request.approvalAvailable === false) {
    return { outcome: "deny", reason: "Operator approval is unavailable" };
  }
  return { outcome: "approval_required", reason: "Operator approval is required before execution" };
}

function isNormalizedRule(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    return normalizeScopeRule(value) === value;
  } catch {
    return false;
  }
}
