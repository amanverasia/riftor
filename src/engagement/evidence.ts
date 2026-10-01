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
  request: { method: "HEAD"; url: string; resolvedAddresses: string[]; connectedAddress: string };
  response: { status: number; statusText: string; headers: Record<string, string> };
}

export interface DnsLookupEvidence extends EvidenceMetadata {
  activity: "dns_lookup";
  query: { types: ["A", "AAAA"] };
  response: { A: string[]; AAAA: string[] };
}

export interface TlsCertificateEvidence extends EvidenceMetadata {
  activity: "tls_certificate";
  request: { protocol: "TLS"; port: 443; serverName: string; connectedAddress: string };
  response: {
    certificatePresent: boolean;
    subject: Record<string, string> | null;
    issuer: Record<string, string> | null;
    validFrom: string | null;
    validTo: string | null;
    fingerprint256: string | null;
    subjectAltNames: string[];
    protocol: string | null;
    authorized: boolean;
    authorizationError: string | null;
    error?: string;
  };
}

export type EvidenceRecord = HttpHeadersEvidence | DnsLookupEvidence | TlsCertificateEvidence;
