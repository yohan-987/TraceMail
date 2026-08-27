import { fetchWithTimeout, TimeoutError } from "../utils/http";
import type { EvidenceAvailability } from "../schemas/types";

export interface GeoIpLookupResult {
  ip: string;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  organization: string | null;
  hosting: string | null;
  status: EvidenceAvailability;
}

export interface GeoIpProvider {
  lookup(ip: string): Promise<GeoIpLookupResult>;
}

function empty(ip: string, status: EvidenceAvailability): GeoIpLookupResult {
  return {
    ip,
    country: null,
    region: null,
    city: null,
    isp: null,
    asn: null,
    organization: null,
    hosting: null,
    status,
  };
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/**
 * ip-api.com (or any compatible JSON endpoint). Pluggable: pass a
 * different baseUrl / fetchImpl. Missing fields stay null — never guessed.
 */
export function createIpApiProvider(options: {
  baseUrl: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}): GeoIpProvider {
  const timeoutMs = options.timeoutMs ?? 5000;
  const fetchImpl = options.fetchImpl ?? fetch;
  const baseUrl = options.baseUrl.replace(/\/$/, "");

  return {
    async lookup(ip: string): Promise<GeoIpLookupResult> {
      const url = `${baseUrl}/${encodeURIComponent(ip)}`;
      try {
        const res = await fetchWithTimeout(url, { method: "GET" }, timeoutMs, fetchImpl);
        if (!res.ok) return empty(ip, res.status >= 500 ? "ERROR" : "UNAVAILABLE");

        let body: unknown;
        try {
          body = await res.json();
        } catch {
          return empty(ip, "ERROR");
        }
        if (!body || typeof body !== "object") return empty(ip, "ERROR");

        const obj = body as Record<string, unknown>;
        const apiStatus = asString(obj.status)?.toLowerCase();
        if (apiStatus === "fail") return empty(ip, "UNAVAILABLE");

        const country = asString(obj.country);
        const region = asString(obj.regionName) ?? asString(obj.region);
        const city = asString(obj.city);
        const isp = asString(obj.isp);
        const organization = asString(obj.org);
        const asn = asString(obj.as) ?? asString(obj.asn);
        const hosting =
          typeof obj.hosting === "boolean"
            ? obj.hosting
              ? "hosting"
              : "not_hosting"
            : asString(obj.hosting);

        const hasAny = Boolean(country || region || city || isp || asn || organization || hosting);
        return {
          ip,
          country,
          region,
          city,
          isp,
          asn,
          organization,
          hosting,
          status: hasAny ? "AVAILABLE" : "INCONCLUSIVE",
        };
      } catch (err) {
        if (err instanceof TimeoutError) return empty(ip, "ERROR");
        return empty(ip, "ERROR");
      }
    },
  };
}

/** Used when GEOIP_API_URL is unset — no network, no fabricated location. */
export function createUnavailableGeoIpProvider(): GeoIpProvider {
  return {
    async lookup(ip: string): Promise<GeoIpLookupResult> {
      return empty(ip, "UNAVAILABLE");
    },
  };
}

export function geoIpProviderFromEnv(): GeoIpProvider {
  const baseUrl = process.env.GEOIP_API_URL?.trim();
  if (!baseUrl) return createUnavailableGeoIpProvider();
  return createIpApiProvider({
    baseUrl,
    timeoutMs: Number(process.env.GEOIP_TIMEOUT_MS ?? 5000),
  });
}
