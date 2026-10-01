interface EvidenceMetadata {
  id: string;
  engagementId: string;
  capturedAt: string;
  target: string;
  previousSha256: string | null;
  sha256: string;
}

export interface HttpHeadersEvidence extends EvidenceMetadata {
  activity: "http_headers";
  request: { method: "HEAD"; url: string };
  response: { status: number; statusText: string; headers: Record<string, string> };
}

export interface DnsLookupEvidence extends EvidenceMetadata {
  activity: "dns_lookup";
  query: { types: ["A", "AAAA"] };
  response: { A: string[]; AAAA: string[] };
}

export type EvidenceRecord = HttpHeadersEvidence | DnsLookupEvidence;
