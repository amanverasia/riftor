import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { createDnsLookupTool } from "../dist/security/dns-lookup.js";
import { createHttpHeadersTool } from "../dist/security/http-headers.js";
import { createTlsCertificateTool } from "../dist/security/tls-certificate.js";

function engagement() {
  const now = Date.now();
  return {
    id: "adapter-success",
    name: "adapter success",
    createdAt: new Date(now).toISOString(),
    authorization: {
      reference: "AUTH-1",
      authorizedBy: "Operator",
      startsAt: new Date(now - 1_000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      activities: ["http_headers", "dns_lookup", "tls_certificate"],
    },
    scope: { include: ["example.com"], exclude: [] },
  };
}

async function withTempDir(run) {
  const directory = await mkdtemp(join(tmpdir(), "riftor-adapter-test-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("approved HTTP and DNS adapters pin, audit, and persist successful observations", async () => {
  await withTempDir(async (directory) => {
    const engagementStore = new EngagementStore(directory);
    const evidenceStore = new EvidenceStore(directory);
    await engagementStore.save(engagement());
    let approvals = 0;
    const approve = async () => { approvals += 1; return true; };

    const httpTool = createHttpHeadersTool(engagementStore, evidenceStore, approve, {
      createResolver: () => ({
        resolve4: async () => ["93.184.216.34"],
        resolve6: async () => [],
        cancel() {},
      }),
      sendHeadRequest: async (_url, _host, address) => ({
        status: 200,
        statusText: "OK",
        headers: { server: "fixture" },
      }),
    });
    const httpResult = await httpTool.execute("http-1", { target: "example.com" }, undefined, undefined, {});
    assert.match(httpResult.content[0].text, /HTTP 200 OK/);

    const dnsTool = createDnsLookupTool(engagementStore, evidenceStore, approve, {
      createResolver: () => ({
        resolve4: async () => ["93.184.216.34"],
        resolve6: async () => ["2606:2800:220:1:248:1893:25c8:1946"],
        cancel() {},
      }),
    });
    const dnsResult = await dnsTool.execute("dns-1", { target: "example.com" }, undefined, undefined, {});
    assert.match(dnsResult.content[0].text, /A: 93\.184\.216\.34/);

    let tlsEndpoint;
    const tlsTool = createTlsCertificateTool(engagementStore, evidenceStore, approve, {
      createResolver: () => ({
        resolve4: async () => ["93.184.216.34"],
        resolve6: async () => [],
        cancel() {},
      }),
      inspectLeaf: async (host, address) => {
        tlsEndpoint = { host, address };
        return {
          certificatePresent: true,
          subject: { CN: "example.com" },
          issuer: { CN: "Example Test CA" },
          validFrom: "Jan 1 00:00:00 2026 GMT",
          validTo: "Jan 1 00:00:00 2027 GMT",
          fingerprint256: "AA:BB",
          subjectAltNames: ["DNS:example.com"],
          protocol: "TLSv1.3",
          authorized: true,
          authorizationError: null,
        };
      },
    });
    const tlsResult = await tlsTool.execute("tls-1", { target: "example.com" }, undefined, undefined, {});
    assert.match(tlsResult.content[0].text, /TLSv1\.3/);
    assert.deepEqual(tlsEndpoint, { host: "example.com", address: "93.184.216.34" });
    assert.equal(approvals, 3);

    const evidence = await evidenceStore.list();
    assert.deepEqual(evidence.map((record) => record.activity), ["http_headers", "dns_lookup", "tls_certificate"]);
    if (evidence[0].activity !== "http_headers") throw new Error("Expected HTTP evidence first");
    assert.equal(evidence[0].request.connectedAddress, "93.184.216.34");
    assert.deepEqual(evidence[0].request.resolvedAddresses, ["93.184.216.34"]);
    if (evidence[1].activity !== "dns_lookup") throw new Error("Expected DNS evidence second");
    assert.deepEqual(evidence[1].response.AAAA, ["2606:2800:220:1:248:1893:25c8:1946"]);
    if (evidence[2].activity !== "tls_certificate") throw new Error("Expected TLS evidence third");
    assert.equal(evidence[2].request.serverName, "example.com");
    assert.equal(evidence[2].request.connectedAddress, "93.184.216.34");
    assert.equal(evidence[2].response.authorized, true);

    await engagementStore.save(null);
    assert.equal(await engagementStore.load(), null);
  });
});
