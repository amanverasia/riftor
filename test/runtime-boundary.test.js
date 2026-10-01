import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createAgentSession, DefaultResourceLoader } from "@earendil-works/pi-coding-agent";
import { EvidenceStore } from "../dist/engagement/evidence-store.js";
import { EngagementStore } from "../dist/engagement/store.js";
import { createDnsLookupTool } from "../dist/security/dns-lookup.js";
import { createHttpHeadersTool } from "../dist/security/http-headers.js";
import { createTlsCertificateTool } from "../dist/security/tls-certificate.js";

test("embedded Pi session exposes only Riftor's policy-gated tools and no discovered extensions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "riftor-runtime-boundary-"));
  const agentDir = join(directory, "agent-config");
  const store = new EngagementStore(directory);
  const evidence = new EvidenceStore(directory);
  const tools = [
    createHttpHeadersTool(store, evidence, async () => false),
    createDnsLookupTool(store, evidence, async () => false),
    createTlsCertificateTool(store, evidence, async () => false),
  ];
  const resourceLoader = new DefaultResourceLoader({
    cwd: directory,
    agentDir,
    noExtensions: true,
    noSkills: true,
    noPromptTemplates: true,
    noThemes: true,
    noContextFiles: true,
  });
  let session;
  try {
    ({ session } = await createAgentSession({
      cwd: directory,
      agentDir,
      resourceLoader,
      tools: tools.map((tool) => tool.name),
      customTools: tools,
    }));
    assert.deepEqual(session.getActiveToolNames().sort(), [
      "riftor_dns_lookup",
      "riftor_http_headers",
      "riftor_tls_certificate",
    ]);
    assert.deepEqual(resourceLoader.getExtensions().extensions, []);
    assert.deepEqual(resourceLoader.getSkills().skills, []);
  } finally {
    session?.dispose();
    await rm(directory, { recursive: true, force: true });
  }
});
