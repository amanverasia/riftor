export interface HttpHeadersEvidence {
  id: string;
  engagementId: string;
  capturedAt: string;
  target: string;
  activity: "http_headers";
  request: { method: "HEAD"; url: string };
  response: { status: number; statusText: string; headers: Record<string, string> };
  previousSha256: string | null;
  sha256: string;
}
