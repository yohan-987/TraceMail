import type {
  EmailAddress,
  EmailRecord,
  GeoIpRecord,
  GraphProvenance,
  InfrastructureGraph,
  InfrastructureGraphEdge,
  InfrastructureGraphNode,
  InfrastructureGraphNodeType,
} from "../schemas/types";
import { classifyIp } from "../utils/ip";

const PLACEHOLDERS = new Set(["unknown", "n/a", "na", "unavailable", "none", "null", "-", "hosting", "not_hosting"]);

const LOCATION_INTERPRETATION = "Infrastructure location ≠ attacker identity";

type AddressRole = "from" | "to" | "cc" | "bcc" | "reply_to" | "return_path";

const ADDRESS_RELATIONSHIP: Record<AddressRole, string> = {
  from: "has_from_address",
  to: "has_to_address",
  cc: "has_cc_address",
  bcc: "has_bcc_address",
  reply_to: "has_reply_to_address",
  return_path: "has_return_path_address",
};

function usable(value: string | null | undefined): value is string {
  if (value == null) return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  return !PLACEHOLDERS.has(trimmed.toLowerCase());
}

function nodeId(type: string, key: string): string {
  return `${type}:${key}`;
}

/**
 * Pure transformation of a stored EmailRecord into a provenance-aware
 * infrastructure graph. Does not parse email, run ML/LLM, or call GeoIP/DNS.
 */
export function buildInfrastructureGraph(record: EmailRecord): InfrastructureGraph {
  const nodes = new Map<string, InfrastructureGraphNode>();
  const edges = new Map<string, InfrastructureGraphEdge>();

  function addNode(
    type: InfrastructureGraphNodeType,
    key: string,
    label: string,
    metadata?: Record<string, unknown>
  ): string {
    const id = nodeId(type.toLowerCase().replace(/_/g, "-"), key);
    const existing = nodes.get(id);
    if (existing) {
      if (metadata) existing.metadata = { ...existing.metadata, ...metadata };
      return id;
    }
    const node: InfrastructureGraphNode = {
      id,
      type,
      label,
      status: "AVAILABLE",
    };
    if (metadata && Object.keys(metadata).length > 0) node.metadata = metadata;
    nodes.set(id, node);
    return id;
  }

  function addEdge(
    source: string,
    target: string,
    relationship: string,
    provenance: GraphProvenance,
    evidence?: string[]
  ): void {
    const id = `${source}|${relationship}|${target}`;
    const existing = edges.get(id);
    if (existing) {
      if (evidence?.length) {
        const merged = new Set([...(existing.evidence ?? []), ...evidence]);
        existing.evidence = [...merged];
      }
      return;
    }
    const edge: InfrastructureGraphEdge = { source, target, relationship, provenance };
    if (evidence && evidence.length > 0) edge.evidence = evidence;
    edges.set(id, edge);
  }

  const emailNodeId = addNode("EMAIL", record.emailId, record.parsedEmail?.subject || record.emailId, {
    emailId: record.emailId,
  });

  addAddressNodes(record, emailNodeId, addNode, addEdge);
  addDomainNodes(record, emailNodeId, addNode, addEdge);
  addUrlNodes(record, emailNodeId, addNode, addEdge);
  addIpNodes(record, emailNodeId, addNode, addEdge);
  addDnsResolutions(record, addNode, addEdge);
  addIpIntelligence(record, addNode, addEdge);

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
  };
}

function addAddressNodes(
  record: EmailRecord,
  emailNodeId: string,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  const parsed = record.parsedEmail;
  if (!parsed) return;

  const groups: { role: AddressRole; addresses: EmailAddress[]; evidence: string }[] = [
    { role: "from", addresses: parsed.from, evidence: "From header" },
    { role: "to", addresses: parsed.to, evidence: "To header" },
    { role: "cc", addresses: parsed.cc, evidence: "CC header" },
    { role: "bcc", addresses: parsed.bcc, evidence: "BCC header" },
    { role: "reply_to", addresses: parsed.replyTo, evidence: "Reply-To header" },
    { role: "return_path", addresses: parsed.returnPath, evidence: "Return-Path header" },
  ];

  for (const group of groups) {
    for (const addr of group.addresses) {
      if (!usable(addr.email)) continue;
      const email = addr.email.trim().toLowerCase();
      const id = addNode("EMAIL_ADDRESS", email, email, { role: group.role, domain: addr.domain });
      addEdge(emailNodeId, id, ADDRESS_RELATIONSHIP[group.role], "OBSERVED", [group.evidence]);
    }
  }
}

function addDomainNodes(
  record: EmailRecord,
  emailNodeId: string,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  const domains = new Set<string>();
  for (const d of record.iocs?.domains ?? []) {
    if (usable(d) && classifyIp(d) === "INVALID") domains.add(d.trim().toLowerCase());
  }
  for (const d of record.domainAnalysis?.domains ?? []) {
    if (usable(d.domain) && classifyIp(d.domain) === "INVALID") domains.add(d.domain.trim().toLowerCase());
  }
  for (const d of record.infrastructure?.domainIntelligence ?? []) {
    if (usable(d.domain) && classifyIp(d.domain) === "INVALID") domains.add(d.domain.trim().toLowerCase());
  }

  for (const domain of domains) {
    const id = addNode("DOMAIN", domain, domain);
    addEdge(emailNodeId, id, "contains_domain", "OBSERVED", ["IOC domain extraction"]);
  }
}

function hostnameIsIp(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, "");
  return classifyIp(bare) !== "INVALID";
}

function addUrlNodes(
  record: EmailRecord,
  emailNodeId: string,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  const analyzed = new Map((record.urlAnalysis?.urls ?? []).map((u) => [u.url, u]));
  const urls = new Set<string>([...(record.iocs?.urls ?? []), ...analyzed.keys()]);

  for (const raw of urls) {
    if (!usable(raw)) continue;
    const features = analyzed.get(raw);
    let hostname: string | null = features?.hostname ?? null;
    let domain: string | null = features?.domain ?? null;
    let hasIpHost = features?.hasIpHost ?? false;

    if (!hostname) {
      try {
        const parsed = new URL(raw);
        hostname = parsed.hostname.toLowerCase();
        hasIpHost = hostnameIsIp(hostname);
        domain = hasIpHost ? hostname.replace(/^\[|\]$/g, "") : hostname;
      } catch {
        hostname = null;
      }
    }

    const urlId = addNode("URL", raw, raw, hostname ? { hostname, domain } : undefined);
    addEdge(emailNodeId, urlId, "contains_url", "OBSERVED", ["IOC URL extraction"]);

    if (hasIpHost && hostname) {
      const ip = hostname.replace(/^\[|\]$/g, "");
      const classification = classifyIp(ip);
      if (classification === "INVALID") continue;
      const ipId = addNode("IP", ip, ip, { classification });
      addEdge(urlId, ipId, "uses_ip_host", "DETERMINISTIC_ANALYSIS", ["Parsed URL hostname"]);
      continue;
    }

    const host = (hostname && usable(hostname) ? hostname : domain)?.trim().toLowerCase();
    if (!host || hostnameIsIp(host)) continue;
    const domainId = addNode("DOMAIN", host, host);
    addEdge(urlId, domainId, "uses_domain", "DETERMINISTIC_ANALYSIS", ["Parsed URL hostname"]);
  }
}

function addIpNodes(
  record: EmailRecord,
  emailNodeId: string,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  const receivedIps = new Set<string>();
  for (const hop of record.headerAnalysis?.receivedChain ?? []) {
    if (!hop.fromIp) continue;
    const classification = classifyIp(hop.fromIp);
    if (classification === "INVALID") continue;
    receivedIps.add(hop.fromIp);
    const ipId = addNode("IP", hop.fromIp, hop.fromIp, { classification });
    addEdge(emailNodeId, ipId, "contains_received_ip", "OBSERVED", ["Received header"]);
  }

  for (const ip of record.iocs?.ips ?? []) {
    const classification = classifyIp(ip);
    if (classification === "INVALID") continue;
    const ipId = addNode("IP", ip, ip, { classification });
    if (!receivedIps.has(ip)) {
      addEdge(emailNodeId, ipId, "contains_ip", "OBSERVED", ["IOC IP extraction"]);
    }
  }
}

function addDnsResolutions(
  record: EmailRecord,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  for (const intel of record.infrastructure?.domainIntelligence ?? []) {
    if (intel.status !== "AVAILABLE") continue;
    if (!usable(intel.domain) || !intel.resolvedIps || intel.resolvedIps.length === 0) continue;
    const domain = intel.domain.trim().toLowerCase();
    if (classifyIp(domain) !== "INVALID") continue;
    const domainId = addNode("DOMAIN", domain, domain);

    for (const ip of intel.resolvedIps) {
      const classification = classifyIp(ip);
      if (classification === "INVALID") continue;
      const ipId = addNode("IP", ip, ip, { classification });
      addEdge(domainId, ipId, "resolves_to", "EXTERNAL_INTELLIGENCE", ["DNS A-record"]);
    }
  }
}

function geoMetadata(rec: GeoIpRecord, confidence: number | null): Record<string, unknown> | null {
  const meta: Record<string, unknown> = {
    interpretation: LOCATION_INTERPRETATION,
  };
  if (usable(rec.country)) meta.country = rec.country;
  if (usable(rec.region)) meta.region = rec.region;
  if (usable(rec.city)) meta.city = rec.city;
  const extra = rec as GeoIpRecord & { latitude?: unknown; longitude?: unknown };
  if (typeof extra.latitude === "number") meta.latitude = extra.latitude;
  if (typeof extra.longitude === "number") meta.longitude = extra.longitude;
  if (confidence != null) meta.confidence = confidence;

  const hasLocation = "country" in meta || "region" in meta || "city" in meta || "latitude" in meta || "longitude" in meta;
  if (!hasLocation) return null;
  return meta;
}

function addIpIntelligence(
  record: EmailRecord,
  addNode: (type: InfrastructureGraphNodeType, key: string, label: string, metadata?: Record<string, unknown>) => string,
  addEdge: (source: string, target: string, relationship: string, provenance: GraphProvenance, evidence?: string[]) => void
): void {
  const infra = record.infrastructure;
  if (!infra) return;

  for (const rec of infra.ipIntelligence) {
    if (classifyIp(rec.ip) !== "PUBLIC") continue;
    if (rec.status !== "AVAILABLE") continue;

    const ipId = addNode("IP", rec.ip, rec.ip, { classification: "PUBLIC" });

    if (usable(rec.asn)) {
      const asnId = addNode("ASN", rec.asn, rec.asn);
      addEdge(ipId, asnId, "has_asn", "EXTERNAL_INTELLIGENCE", ["GeoIP ASN"]);
    }

    const orgNames = new Set<string>();
    if (usable(rec.organization)) orgNames.add(rec.organization.trim());
    if (usable(rec.isp)) orgNames.add(rec.isp.trim());
    for (const name of orgNames) {
      const orgId = addNode("ORGANIZATION", name.toLowerCase(), name);
      addEdge(ipId, orgId, "hosted_by", "EXTERNAL_INTELLIGENCE", ["GeoIP organization/ISP"]);
    }

    const confidence = rec.ip === infra.candidateIp ? infra.confidence : null;
    const geo = geoMetadata(rec, confidence);
    if (geo) {
      const label = [rec.city, rec.region, rec.country].filter((p) => usable(p)).join(", ") || rec.ip;
      const geoId = addNode("GEOLOCATION", rec.ip, label, geo);
      addEdge(ipId, geoId, "located_in", "EXTERNAL_INTELLIGENCE", ["GeoIP"]);
    }
  }
}
