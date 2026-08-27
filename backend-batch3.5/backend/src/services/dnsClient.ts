import dns from "dns";
import type { EvidenceAvailability } from "../schemas/types";

export interface DnsLookupResult {
  domain: string;
  resolvedIps: string[] | null;
  mxHosts: string[] | null;
  status: EvidenceAvailability;
}

export interface DnsProvider {
  lookup(domain: string): Promise<DnsLookupResult>;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("DNS_TIMEOUT")), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

export function createNodeDnsProvider(options?: { timeoutMs?: number }): DnsProvider {
  const timeoutMs = options?.timeoutMs ?? 2000;
  const resolver = new dns.promises.Resolver();

  return {
    async lookup(domain: string): Promise<DnsLookupResult> {
      const empty = (status: EvidenceAvailability): DnsLookupResult => ({
        domain,
        resolvedIps: null,
        mxHosts: null,
        status,
      });

      try {
        const [aResult, mxResult] = await Promise.allSettled([
          withTimeout(resolver.resolve4(domain), timeoutMs),
          withTimeout(resolver.resolveMx(domain), timeoutMs),
        ]);

        const resolvedIps = aResult.status === "fulfilled" ? aResult.value : null;
        const mxHosts =
          mxResult.status === "fulfilled"
            ? mxResult.value
                .sort((a, b) => a.priority - b.priority)
                .map((mx) => mx.exchange)
            : null;

        const aTimedOut =
          aResult.status === "rejected" &&
          aResult.reason instanceof Error &&
          aResult.reason.message === "DNS_TIMEOUT";
        const mxTimedOut =
          mxResult.status === "rejected" &&
          mxResult.reason instanceof Error &&
          mxResult.reason.message === "DNS_TIMEOUT";

        if (aTimedOut && mxTimedOut) return empty("ERROR");
        if (!resolvedIps && !mxHosts) {
          if (aTimedOut || mxTimedOut) return empty("ERROR");
          return empty("UNAVAILABLE");
        }

        return {
          domain,
          resolvedIps,
          mxHosts,
          status: "AVAILABLE",
        };
      } catch {
        return empty("ERROR");
      }
    },
  };
}

export function createUnavailableDnsProvider(): DnsProvider {
  return {
    async lookup(domain: string): Promise<DnsLookupResult> {
      return { domain, resolvedIps: null, mxHosts: null, status: "UNAVAILABLE" };
    },
  };
}

export function dnsProviderFromEnv(): DnsProvider {
  if (process.env.DNS_INTEL_ENABLED === "0") return createUnavailableDnsProvider();
  return createNodeDnsProvider({
    timeoutMs: Number(process.env.DNS_TIMEOUT_MS ?? 2000),
  });
}
