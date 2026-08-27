import type {
  DomainIntelligenceRecord,
  EvidenceAvailability,
  GeoIpRecord,
  HeaderAnalysis,
  InfrastructureAssessment,
  IOCSet,
  RiskEvidenceItem,
} from "../schemas/types";
import { classifyIp } from "../utils/ip";
import type { GeoIpProvider } from "../services/geoipClient";
import type { DnsProvider } from "../services/dnsClient";
import { enrichDomains, summarizeDomainIntelStatus } from "./domainIntelligence";
import {
  CLOUD_VPS_MARKERS,
  KNOWN_SUSPICIOUS_IPS,
  SUSPICIOUS_ASNS,
} from "../config/infrastructureSignals";

const MAX_PUBLIC_IPS = 5;

export function publicCandidateIps(headerAnalysis: HeaderAnalysis, iocs: IOCSet): string[] {
  const fromReceived = headerAnalysis.receivedChain
    .map((hop) => hop.fromIp)
    .filter((ip): ip is string => Boolean(ip));
  const combined = [...fromReceived, ...iocs.ips];
  const unique: string[] = [];
  for (const ip of combined) {
    if (unique.includes(ip)) continue;
    if (classifyIp(ip) !== "PUBLIC") continue;
    unique.push(ip);
    if (unique.length >= MAX_PUBLIC_IPS) break;
  }
  return unique;
}

function combineAvailability(statuses: EvidenceAvailability[]): EvidenceAvailability {
  if (statuses.length === 0) return "NOT_APPLICABLE";
  if (statuses.some((s) => s === "AVAILABLE")) return "AVAILABLE";
  if (statuses.every((s) => s === "NOT_APPLICABLE")) return "NOT_APPLICABLE";
  if (statuses.some((s) => s === "ERROR") && statuses.every((s) => s === "ERROR" || s === "UNAVAILABLE" || s === "NOT_APPLICABLE")) {
    return "ERROR";
  }
  if (statuses.every((s) => s === "UNAVAILABLE" || s === "NOT_APPLICABLE")) return "UNAVAILABLE";
  return "INCONCLUSIVE";
}

function looksLikeCloudVps(record: GeoIpRecord): boolean {
  const blob = `${record.isp ?? ""} ${record.organization ?? ""} ${record.hosting ?? ""}`.toLowerCase();
  return CLOUD_VPS_MARKERS.some((marker) => blob.includes(marker));
}

export function infrastructureEvidence(options: {
  geoRecords: GeoIpRecord[];
  publicIps: string[];
}): RiskEvidenceItem[] {
  const { geoRecords, publicIps } = options;
  const evidence: RiskEvidenceItem[] = [];

  for (const ip of publicIps) {
    if (KNOWN_SUSPICIOUS_IPS.has(ip)) {
      evidence.push({
        type: "known_suspicious_infrastructure",
        severity: "high",
        weight: 30,
        message: `Candidate IP ${ip} matched a configured suspicious-infrastructure list.`,
        evidence: { ip },
        category: "infrastructure",
        provenance: "EXTERNAL_INTELLIGENCE",
      });
    }
  }

  for (const rec of geoRecords) {
    if (rec.status !== "AVAILABLE") continue;
    if (rec.asn && SUSPICIOUS_ASNS.has(rec.asn)) {
      evidence.push({
        type: "suspicious_asn",
        severity: "medium",
        weight: 20,
        message: `GeoIP reported ASN ${rec.asn} which is on the configured suspicious-ASN list.`,
        evidence: { ip: rec.ip, asn: rec.asn },
        category: "infrastructure",
        provenance: "EXTERNAL_INTELLIGENCE",
      });
    }
    if (looksLikeCloudVps(rec)) {
      evidence.push({
        type: "cloud_vps_indicator",
        severity: "low",
        weight: 15,
        message: `GeoIP organization/ISP for ${rec.ip} matches a cloud/VPS hosting marker. This is probable infrastructure, not attacker location.`,
        evidence: { ip: rec.ip, isp: rec.isp, organization: rec.organization },
        category: "infrastructure",
        provenance: "INFERRED",
      });
    }
  }

  const distinctPublic = [...new Set(publicIps)];
  if (distinctPublic.length >= 2) {
    evidence.push({
      type: "multiple_anomalous_source_ips",
      severity: "medium",
      weight: 20,
      message: `Multiple distinct public candidate IPs were observed in the message (${distinctPublic.length}). This is an observed routing fact, not an identity.`,
      evidence: { ips: distinctPublic },
      category: "infrastructure",
      provenance: "OBSERVED",
    });
  }

  const confirmedIntel =
    publicIps.some((ip) => KNOWN_SUSPICIOUS_IPS.has(ip)) ||
    geoRecords.some((rec) => rec.status === "AVAILABLE" && rec.asn && SUSPICIOUS_ASNS.has(rec.asn));
  if (confirmedIntel) {
    evidence.push({
      type: "confirmed_external_intelligence",
      severity: "high",
      weight: 40,
      message:
        "An external intelligence list matched a candidate IP or ASN. This is list-based intel, not a fabricated reputation score.",
      evidence: { publicIps },
      category: "infrastructure",
      provenance: "EXTERNAL_INTELLIGENCE",
    });
  }

  return evidence;
}

export async function analyzeInfrastructure(options: {
  emailId: string;
  headerAnalysis: HeaderAnalysis;
  iocs: IOCSet;
  geoIp: GeoIpProvider;
  dns: DnsProvider;
}): Promise<{
  infrastructure: InfrastructureAssessment;
  domainIntelligence: DomainIntelligenceRecord[];
  evidence: RiskEvidenceItem[];
}> {
  const publicIps = publicCandidateIps(options.headerAnalysis, options.iocs);
  const geoRecords: GeoIpRecord[] = [];
  for (const ip of publicIps) {
    const lookup = await options.geoIp.lookup(ip);
    geoRecords.push({
      ip: lookup.ip,
      country: lookup.country,
      region: lookup.region,
      city: lookup.city,
      isp: lookup.isp,
      asn: lookup.asn,
      organization: lookup.organization,
      hosting: lookup.hosting,
      status: lookup.status,
    });
  }

  const domainIntelligence = await enrichDomains(options.iocs.domains, options.dns);
  const evidence = infrastructureEvidence({ geoRecords, publicIps });

  const geoStatus = geoRecords.length === 0 ? "NOT_APPLICABLE" : combineAvailability(geoRecords.map((r) => r.status));
  const dnsStatus = summarizeDomainIntelStatus(domainIntelligence);
  const status = combineAvailability([geoStatus, dnsStatus]);

  const primary = geoRecords.find((r) => r.status === "AVAILABLE") ?? null;

  const infrastructure: InfrastructureAssessment = {
    emailId: options.emailId,
    candidateIp: publicIps[0] ?? null,
    country: primary?.country ?? null,
    region: primary?.region ?? null,
    city: primary?.city ?? null,
    isp: primary?.isp ?? null,
    asn: primary?.asn ?? null,
    confidence: primary ? 0.5 : null,
    status,
    ipIntelligence: geoRecords,
    domainIntelligence,
    interpretation: "probable_infrastructure",
  };

  return { infrastructure, domainIntelligence, evidence };
}
