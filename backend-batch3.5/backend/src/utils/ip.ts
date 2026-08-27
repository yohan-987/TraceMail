import net from "net";
import type { IpClassification } from "../schemas/types";

/**
 * Classifies an IP address for forensic purposes. Only PUBLIC addresses
 * should ever be sent to GeoIP (Batch 4) — private/loopback/link-local/
 * invalid addresses carry no meaningful location information and must
 * not be queried.
 */
export function classifyIp(ip: string): IpClassification {
  const version = net.isIP(ip);
  if (version === 0) return "INVALID";

  if (version === 4) {
    const parts = ip.split(".").map(Number);
    const [a, b] = parts;
    if (a === 127) return "LOOPBACK";
    if (a === 10) return "PRIVATE";
    if (a === 172 && b >= 16 && b <= 31) return "PRIVATE";
    if (a === 192 && b === 168) return "PRIVATE";
    if (a === 169 && b === 254) return "LINK_LOCAL";
    return "PUBLIC";
  }

  // IPv6
  const lower = ip.toLowerCase();
  if (lower === "::1") return "LOOPBACK";
  if (lower.startsWith("fe80:")) return "LINK_LOCAL"; // fe80::/10
  if (lower.startsWith("fc") || lower.startsWith("fd")) return "PRIVATE"; // fc00::/7 unique local
  return "PUBLIC";
}

// Finds the first IPv4 or IPv6 literal anywhere in a string (e.g. a raw
// Received header line). Prefers the bracketed form `[1.2.3.4]` common
// in Received headers, but falls back to a bare match.
const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
const IPV6_RE = /\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b/;

export function findFirstIp(text: string): string | null {
  const bracketed = text.match(/\[([^\]]+)\]/);
  if (bracketed && net.isIP(bracketed[1]) !== 0) return bracketed[1];

  const v4 = text.match(IPV4_RE);
  if (v4 && net.isIP(v4[1]) !== 0) return v4[1];

  const v6 = text.match(IPV6_RE);
  if (v6 && net.isIP(v6[1]) !== 0) return v6[1];

  return null;
}
