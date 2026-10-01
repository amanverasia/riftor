import { Resolver } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { Engagement } from "../engagement/types.js";
import { isTargetInScope } from "./scope.js";

export interface DnsAddressResolver {
  resolve4(host: string): Promise<string[]>;
  resolve6(host: string): Promise<string[]>;
  cancel(): void;
}

const nonPublicV4 = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const) {
  nonPublicV4.addSubnet(network, prefix, "ipv4");
}

const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
const nonPublicV6 = new BlockList();
for (const [network, prefix] of [
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["::ffff:0:0", 96],
] as const) {
  nonPublicV6.addSubnet(network, prefix, "ipv6");
}

export async function resolveScopedAddresses(
  host: string,
  engagement: Engagement,
  createResolver: () => DnsAddressResolver = () => new Resolver({ timeout: 5_000, tries: 1 }),
): Promise<string[]> {
  const family = isIP(host);
  if (family) {
    if (!isTargetInScope(host, engagement.scope.include, engagement.scope.exclude)) {
      throw new Error("Resolved address is outside engagement scope");
    }
    return [host];
  }

  const resolver = createResolver();
  let addresses: string[];
  try {
    const [ipv4, ipv6] = await Promise.all([
      resolveOrEmpty(() => resolver.resolve4(host)),
      resolveOrEmpty(() => resolver.resolve6(host)),
    ]);
    addresses = [...ipv4, ...ipv6];
  } finally {
    resolver.cancel();
  }

  const unique = [...new Set(addresses)];
  if (!unique.length) throw new Error("Target hostname resolved to no A or AAAA addresses");
  for (const address of unique) {
    if (!isPublicAddress(address) && !isTargetInScope(address, engagement.scope.include, engagement.scope.exclude)) {
      throw new Error(`Target hostname resolves to an IP outside explicit engagement scope: ${address}`);
    }
    if (!isTargetInScope(address, engagement.scope.include, engagement.scope.exclude) && isExplicitlyExcluded(address, engagement)) {
      throw new Error(`Target hostname resolves to an explicitly excluded IP: ${address}`);
    }
  }
  return unique;
}

function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !nonPublicV4.check(address, "ipv4");
  if (family !== 6 || !globalV6.check(address, "ipv6")) return false;
  return !nonPublicV6.check(address, "ipv6");
}

function isExplicitlyExcluded(address: string, engagement: Engagement): boolean {
  return engagement.scope.exclude.some((rule) => isTargetInScope(address, [rule]));
}

async function resolveOrEmpty(resolve: () => Promise<string[]>): Promise<string[]> {
  try {
    return await resolve();
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && (error.code === "ENODATA" || error.code === "ENOTFOUND")) {
      return [];
    }
    throw error;
  }
}
