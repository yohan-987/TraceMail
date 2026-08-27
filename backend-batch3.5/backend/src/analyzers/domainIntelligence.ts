import type { DomainIntelligenceRecord, EvidenceAvailability } from "../schemas/types";
import type { DnsProvider } from "../services/dnsClient";

const MAX_DOMAINS = 8;

export async function enrichDomains(
  domains: string[],
  provider: DnsProvider
): Promise<DomainIntelligenceRecord[]> {
  const unique = [...new Set(domains.map((d) => d.toLowerCase()).filter(Boolean))].slice(0, MAX_DOMAINS);
  const results: DomainIntelligenceRecord[] = [];

  for (const domain of unique) {
    const lookup = await provider.lookup(domain);
    results.push({
      domain,
      resolvedIps: lookup.resolvedIps,
      mxHosts: lookup.mxHosts,
      registrar: null,
      domainAgeDays: null,
      hostingOrganization: null,
      status: lookup.status,
    });
  }

  return results;
}

export function summarizeDomainIntelStatus(records: DomainIntelligenceRecord[]): EvidenceAvailability {
  if (records.length === 0) return "NOT_APPLICABLE";
  if (records.some((r) => r.status === "AVAILABLE")) return "AVAILABLE";
  if (records.every((r) => r.status === "ERROR")) return "ERROR";
  if (records.every((r) => r.status === "UNAVAILABLE")) return "UNAVAILABLE";
  return "INCONCLUSIVE";
}
