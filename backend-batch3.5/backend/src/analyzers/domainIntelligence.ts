import type {
  DomainIntelligenceRecord,
  EvidenceAvailability,
} from "../schemas/types";
import type { DnsProvider } from "../services/dnsClient";

interface WhoisLookupResult {
  registrar: string | null;
  domainAgeDays: number | null;
}

export async function lookupWhois(
  domain: string
): Promise<WhoisLookupResult> {
  try {
    const whoisJsonModule: any = await import("whois-json");
    const whoisJson = whoisJsonModule.default ?? whoisJsonModule;

    const result = await whoisJson(domain);

    console.log(
      "RAW WHOIS RESULT:",
      JSON.stringify(result, null, 2)
    );

    /*
     * whois-json usually returns a flat WHOIS record.
     * For responses that are nested, use the first nested object
     * containing useful WHOIS fields.
     */
    const record: any =
      result &&
      typeof result === "object" &&
      !Array.isArray(result)
        ? (
            "registrar" in result ||
            "creationDate" in result ||
            "organisation" in result ||
            "registrantOrganization" in result ||
            "created" in result ||
            "registrationDate" in result
          )
          ? result
          : Object.values(result as Record<string, unknown>).find(
              (value) =>
                value !== null &&
                typeof value === "object" &&
                !Array.isArray(value)
            ) ?? result
        : result;

    console.log(
      "NORMALIZED WHOIS RECORD:",
      JSON.stringify(record, null, 2)
    );

    /*
     * whois-json uses camelCase fields for common WHOIS records,
     * but alternate field names are supported for other TLDs.
     */
    const registrarRaw: string | undefined =
      typeof record?.registrar === "string"
        ? record.registrar
        : typeof record?.organisation === "string"
        ? record.organisation
        : typeof record?.registrantOrganization === "string"
        ? record.registrantOrganization
        : undefined;

    const creationDateRaw: string | undefined =
      typeof record?.creationDate === "string"
        ? record.creationDate
        : typeof record?.created === "string"
        ? record.created
        : typeof record?.registrationDate === "string"
        ? record.registrationDate
        : undefined;

    /*
     * Treat an explicitly redacted/withheld registrar as unavailable.
     * Never invent a domain age when the creation date is unavailable.
     */
    const isRedacted =
      !registrarRaw ||
      /redacted|privacy|withheld/i.test(registrarRaw);

    const registrar = isRedacted ? null : registrarRaw;

    let domainAgeDays: number | null = null;

    if (!isRedacted && creationDateRaw) {
      const created = new Date(creationDateRaw);

      if (!Number.isNaN(created.getTime())) {
        const now = new Date();

        const createdUtc = Date.UTC(
          created.getUTCFullYear(),
          created.getUTCMonth(),
          created.getUTCDate()
        );

        const nowUtc = Date.UTC(
          now.getUTCFullYear(),
          now.getUTCMonth(),
          now.getUTCDate()
        );

        domainAgeDays = Math.floor(
          (nowUtc - createdUtc) / 86_400_000
        );
      }
    }

    return {
      registrar,
      domainAgeDays,
    };
  } catch {
    /*
     * WHOIS network failure, unsupported TLD, rate limit, or
     * malformed response: treat WHOIS evidence as unavailable.
     */
    return {
      registrar: null,
      domainAgeDays: null,
    };
  }
}

const MAX_DOMAINS = 8;

export async function enrichDomains(
  domains: string[],
  provider: DnsProvider
): Promise<DomainIntelligenceRecord[]> {
  const unique = [
    ...new Set(
      domains
        .map((d) => d.toLowerCase())
        .filter(Boolean)
    ),
  ].slice(0, MAX_DOMAINS);

  const results: DomainIntelligenceRecord[] = [];

  for (const domain of unique) {
    const lookup = await provider.lookup(domain);
    const whois = await lookupWhois(domain);

    results.push({
      domain,
      resolvedIps: lookup.resolvedIps,
      mxHosts: lookup.mxHosts,
      registrar: whois.registrar,
      domainAgeDays: whois.domainAgeDays,
      hostingOrganization: null,
      status: lookup.status,
    });
  }

  return results;
}

export function summarizeDomainIntelStatus(
  records: DomainIntelligenceRecord[]
): EvidenceAvailability {
  if (records.length === 0) return "NOT_APPLICABLE";

  if (records.some((r) => r.status === "AVAILABLE")) {
    return "AVAILABLE";
  }

  if (records.every((r) => r.status === "ERROR")) {
    return "ERROR";
  }

  if (records.every((r) => r.status === "UNAVAILABLE")) {
    return "UNAVAILABLE";
  }

  return "INCONCLUSIVE";
}