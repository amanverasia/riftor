import assert from "node:assert/strict";
import test from "node:test";
import { resolveScopedAddresses } from "../dist/security/target-resolution.js";

function engagement({ include = ["example.com"], exclude = [] } = {}) {
  return {
    id: "resolution-test",
    name: "resolution test",
    createdAt: new Date().toISOString(),
    authorization: {
      reference: "AUTH-1",
      authorizedBy: "Operator",
      startsAt: new Date(Date.now() - 1_000).toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      activities: ["http_headers", "tls_certificate"],
    },
    scope: { include, exclude },
  };
}

function resolver(addresses) {
  return () => ({
    resolve4: async () => addresses.v4 ?? [],
    resolve6: async () => addresses.v6 ?? [],
    cancel() {},
  });
}

test("domain resolution rejects private addresses unless an IP scope rule authorizes them", async () => {
  await assert.rejects(
    resolveScopedAddresses("example.com", engagement(), resolver({ v4: ["127.0.0.1"] })),
    /outside explicit engagement scope/,
  );
  const explicitlyAuthorized = engagement({ include: ["example.com", "127.0.0.0/8"] });
  assert.deepEqual(
    await resolveScopedAddresses("example.com", explicitlyAuthorized, resolver({ v4: ["127.0.0.1"] })),
    ["127.0.0.1"],
  );
});

test("domain resolution rejects a mixed public/private answer set and excluded addresses", async () => {
  await assert.rejects(
    resolveScopedAddresses("example.com", engagement(), resolver({ v4: ["93.184.216.34", "169.254.169.254"] })),
    /outside explicit engagement scope/,
  );
  await assert.rejects(
    resolveScopedAddresses("example.com", engagement({ exclude: ["93.184.216.0/24"] }), resolver({ v4: ["93.184.216.34"] })),
    /explicitly excluded IP/,
  );
});

test("an authorized IP target is pinned without an additional DNS lookup", async () => {
  assert.deepEqual(
    await resolveScopedAddresses("8.8.8.8", engagement({ include: ["8.8.8.8"] }), () => { throw new Error("resolver must not run for an IP literal"); }),
    ["8.8.8.8"],
  );
});
