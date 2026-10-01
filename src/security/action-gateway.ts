import type { EvidenceStore } from "../engagement/evidence-store.js";
import type { EngagementStore } from "../engagement/store.js";
import type { Engagement } from "../engagement/types.js";
import { evaluateAction } from "./policy.js";

export interface AuthorizedAction {
  kind: string;
  activity: string;
  target: string;
  approvalMessage: string;
  signal?: AbortSignal;
  auditDetails?: Record<string, unknown>;
}

export type ActionAuthorization =
  | { allowed: true; engagement: Engagement; release: () => Promise<void>; recheck: () => Promise<string | null> }
  | { allowed: false; reason: string };

export async function authorizeAction(
  action: AuthorizedAction,
  dependencies: {
    engagementStore: EngagementStore;
    evidenceStore: EvidenceStore;
    approve: (message: string) => Promise<boolean>;
  },
): Promise<ActionAuthorization> {
  const { engagementStore, evidenceStore, approve } = dependencies;
  const initialEngagement = await engagementStore.load();
  const request = { target: action.target, activity: action.activity, approvalAvailable: true };
  const initialDecision = evaluateAction(initialEngagement, request);
  if (initialDecision.outcome === "deny") {
    await deny(initialEngagement, initialDecision.reason);
    return { allowed: false, reason: initialDecision.reason };
  }

  try {
    await evidenceStore.list();
  } catch (error) {
    const reason = `Evidence integrity check failed: ${error instanceof Error ? error.message : "unknown error"}`;
    await deny(initialEngagement, reason);
    return { allowed: false, reason };
  }
  if (action.signal?.aborted) {
    await deny(initialEngagement, "Action cancelled before operator approval");
    return { allowed: false, reason: "Action cancelled" };
  }

  const approved = await approve(action.approvalMessage).catch(() => false);
  if (!approved) {
    const reason = "Operator approval was not granted";
    await deny(initialEngagement, reason);
    return { allowed: false, reason };
  }

  const release = await engagementStore.acquireActionLock();
  let keepLock = false;
  try {
    const currentEngagement = await engagementStore.load();
    if (!initialEngagement || !currentEngagement || currentEngagement.id !== initialEngagement.id) {
      const reason = "Active engagement changed during approval";
      await deny(currentEngagement, reason);
      return { allowed: false, reason };
    }
    const finalDecision = evaluateAction(currentEngagement, { ...request, humanApproved: true });
    if (finalDecision.outcome !== "allow") {
      await deny(currentEngagement, finalDecision.reason);
      return { allowed: false, reason: finalDecision.reason };
    }
    if (action.signal?.aborted) {
      await deny(currentEngagement, "Action cancelled before execution");
      return { allowed: false, reason: "Action cancelled" };
    }

    await engagementStore.appendAudit({
      ...action.auditDetails,
      kind: `${action.kind}_started`,
      engagementId: currentEngagement.id,
      target: action.target,
      approvedBy: "operator",
    });
    keepLock = true;
    return {
      allowed: true,
      engagement: currentEngagement,
      release,
      recheck: async () => {
        const decision = evaluateAction(currentEngagement, {
          ...request,
          humanApproved: true,
        });
        if (decision.outcome === "allow") return null;
        await deny(currentEngagement, `Authorization changed before execution: ${decision.reason}`);
        return decision.reason;
      },
    };
  } finally {
    if (!keepLock) await release();
  }

  async function deny(engagement: Engagement | null, reason: string): Promise<void> {
    await engagementStore.appendAudit({
      kind: `${action.kind}_denied`,
      engagementId: engagement?.id,
      target: action.target,
      reason,
    });
  }
}
