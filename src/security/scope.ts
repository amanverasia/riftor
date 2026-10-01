import { BlockList, isIP } from "node:net";

export function normalizeTarget(input: string): string {
  const value = input.trim();
  if (!value) throw new Error("Target cannot be empty");

  const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
  if (url.username || url.password) throw new Error("Targets cannot contain URL credentials");

  let hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    hostname = hostname.slice(1, -1);
  }
  if (!hostname || (!isIP(hostname) && !isValidDomain(hostname))) {
    throw new Error(`Invalid target host: ${input}`);
  }
  return hostname;
}

export function isTargetInScope(
  target: string,
  included: readonly string[],
  excluded: readonly string[] = [],
): boolean {
  let hostname: string;
  try {
    hostname = normalizeTarget(target);
  } catch {
    return false;
  }

  if (excluded.some((rule) => matchesRule(hostname, rule))) return false;
  return included.some((rule) => matchesRule(hostname, rule));
}

export function normalizeScopeRule(input: string): string {
  const rule = input.trim().toLowerCase();
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(2).replace(/\.$/, "");
    if (!isValidDomain(suffix)) throw new Error(`Invalid wildcard domain: ${input}`);
    return `*.${suffix}`;
  }
  const cidr = parseCidr(rule);
  if (cidr) return `${cidr.address.toLowerCase()}/${cidr.prefix}`;
  return normalizeTarget(rule);
}

function matchesRule(hostname: string, rawRule: string): boolean {
  const rule = rawRule.trim().toLowerCase();
  if (!rule) return false;

  if (rule.startsWith("*.")) {
    const suffix = rule.slice(2).replace(/\.$/, "");
    return isValidDomain(suffix) && hostname !== suffix && hostname.endsWith(`.${suffix}`);
  }

  const cidr = parseCidr(rule);
  if (cidr) {
    const version = isIP(hostname);
    if (!version || version !== cidr.version) return false;
    try {
      const block = new BlockList();
      block.addSubnet(cidr.address, cidr.prefix, version === 4 ? "ipv4" : "ipv6");
      return block.check(hostname, version === 4 ? "ipv4" : "ipv6");
    } catch {
      return false;
    }
  }

  try {
    return hostname === normalizeTarget(rule);
  } catch {
    return false;
  }
}

function parseCidr(rule: string): { address: string; prefix: number; version: 4 | 6 } | null {
  const slash = rule.lastIndexOf("/");
  if (slash < 1) return null;

  const address = rule.slice(0, slash);
  const prefixText = rule.slice(slash + 1);
  if (!/^\d+$/.test(prefixText)) return null;

  const version = isIP(address);
  if (version !== 4 && version !== 6) return null;
  const prefix = Number(prefixText);
  const max = version === 4 ? 32 : 128;
  if (prefix > max) return null;
  return { address, prefix, version };
}

function isValidDomain(hostname: string): boolean {
  if (hostname.length > 253 || hostname.length === 0) return false;
  return hostname.split(".").every((label) =>
    label.length > 0 &&
    label.length <= 63 &&
    /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/.test(label),
  );
}
