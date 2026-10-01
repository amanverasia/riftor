export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingConfidence = "confirmed" | "high" | "medium" | "low";
export type FindingStatus = "open" | "resolved" | "accepted";

export interface Finding {
  id: string;
  engagementId: string;
  createdAt: string;
  updatedAt: string;
  title: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  status: FindingStatus;
  target: string;
  description: string;
  remediation: string;
  evidenceIds: string[];
}
