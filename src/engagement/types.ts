export interface EngagementAuthorization {
  reference: string;
  authorizedBy: string;
  startsAt: string;
  expiresAt: string;
  activities: string[];
}

export interface EngagementScope {
  include: string[];
  exclude: string[];
}

export interface Engagement {
  id: string;
  name: string;
  createdAt: string;
  authorization: EngagementAuthorization;
  scope: EngagementScope;
}

export type PolicyDecision =
  | { outcome: "allow"; reason: string }
  | { outcome: "approval_required"; reason: string }
  | { outcome: "deny"; reason: string };
