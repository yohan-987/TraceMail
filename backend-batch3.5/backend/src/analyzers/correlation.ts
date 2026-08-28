import { createHash } from "crypto";
import type {
  CorrelationSignal,
  CorrelationSignalType,
  EmailRecord,
  RelatedEmailMatch,
  RelatedEmailsResponse,
} from "../schemas/types";
import { classifyIp } from "../utils/ip";
import { normalizedSimilarity } from "../utils/levenshtein";

// Batch 5B — lightweight, evidence-based related-email / campaign
// correlation on top of already-stored EmailRecords. Pure transformation:
// never re-runs parsing, ML, LLM, GeoIP, or DNS, and never persists a
// second dataset. Confidence and campaignId are prototype-grade signals
// for investigation triage, never confirmed threat-actor attribution.

// --- Signal weights ------------------------------------------------
// Each signal TYPE contributes at most once to a match's confidence,
// regardless of how many individual values matched (e.g. three shared
// domains still count as one SHARED_DOMAIN contribution) — this stops a
// pile of the same weak signal from masquerading as strong evidence.
// Weights are fixed, non-probabilistic contribution scores, combined
// with a bounded noisy-OR (see combineConfidence) so confidence never
// exceeds 1 and multiple weak signals can outweigh one strong one only
// when they are genuinely independent pieces of evidence.
const SIGNAL_WEIGHT: Record<CorrelationSignalType, number> = {
  SHARED_ATTACHMENT_HASH: 0.5,
  SHARED_IP: 0.4,
  SHARED_URL: 0.35,
  SHARED_INFRASTRUCTURE: 0.3,
  SHARED_DOMAIN: 0.25,
  SENDER_DOMAIN_SIMILARITY: 0.2,
  SUBJECT_SIMILARITY: 0.15,
};

// Below this, a match is not surfaced as "related" at all. Chosen so
// that a single SHARED_DOMAIN or SUBJECT_SIMILARITY signal ALONE never
// clears the bar (0.25 and 0.15 respectively, both < 0.3) — same-domain
// or similar-wording alone is explicitly not proof of a campaign per
// the Batch 5B spec. Any real combination of two signals does clear it.
const MIN_RELATED_CONFIDENCE = 0.3;

const SUBJECT_SIMILARITY_THRESHOLD = 0.6;
const MIN_SUBJECT_LENGTH = 8; // avoid matching on trivial/near-empty subjects

const PLACEHOLDER_VALUES = new Set(["unknown", "n/a", "na", "unavailable", "none", "null", "-"]);

function usable(value: string | null | undefined): value is string {
  if (value == null) return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  return !PLACEHOLDER_VALUES.has(trimmed.toLowerCase());
}

function normalizeSubject(subject: string | null | undefined): string {
  if (!subject) return "";
  return subject
    .toLowerCase()
    .replace(/^(re|fwd?|fw)\s*:\s*/g, "") // strip a single reply/forward prefix
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// --- Per-email extracted fields -------------------------------------
// Computed once per stored record (during index build), reused for every
// comparison — this is what keeps correlation O(n) rather than O(n²).

interface EmailFeatures {
  emailId: string;
  domains: Set<string>;
  urls: Set<string>; // lowercased for comparison
  ips: Set<string>; // PUBLIC only — shared private/loopback relay IPs are not campaign evidence
  hashes: Set<string>;
  senderDomain: string | null;
  senderLookalikeTarget: string | null;
  asn: string | null;
  hostingOrg: string | null; // isp or organization, whichever is usable
  subjectNormalized: string;
  subjectRaw: string | null;
}

function extractFeatures(record: EmailRecord): EmailFeatures {
  const domains = new Set(
    (record.iocs?.domains ?? []).filter(usable).map((d) => d.trim().toLowerCase())
  );
  const urls = new Set(
    (record.iocs?.urls ?? []).filter(usable).map((u) => u.trim().toLowerCase())
  );
  const ips = new Set(
    (record.iocs?.ips ?? []).filter((ip) => classifyIp(ip) === "PUBLIC")
  );
  const hashes = new Set((record.iocs?.hashes ?? []).filter(usable).map((h) => h.trim().toLowerCase()));

  const senderDomain = record.parsedEmail?.from?.[0]?.domain?.trim().toLowerCase() ?? null;
  const senderLookalikeTarget =
    (senderDomain &&
      record.domainAnalysis?.domains.find((d) => d.domain === senderDomain)?.lookalikeOf) ||
    null;

  const infra = record.infrastructure;
  const asn = usable(infra?.asn) ? infra!.asn!.trim().toLowerCase() : null;
  const orgCandidate = infra?.ipIntelligence.find((r) => r.ip === infra.candidateIp);
  const hostingOrg = usable(orgCandidate?.organization)
    ? orgCandidate!.organization!.trim().toLowerCase()
    : usable(orgCandidate?.isp)
      ? orgCandidate!.isp!.trim().toLowerCase()
      : null;

  const subjectRaw = record.parsedEmail?.subject ?? null;

  return {
    emailId: record.emailId,
    domains,
    urls,
    ips,
    hashes,
    senderDomain,
    senderLookalikeTarget,
    asn,
    hostingOrg,
    subjectNormalized: normalizeSubject(subjectRaw),
    subjectRaw,
  };
}

// --- Candidate index --------------------------------------------------
// Inverted indexes built once per request (O(n) over all stored
// records). Candidate generation for a selected email is then just a
// handful of O(1) map lookups keyed by that email's own indicator
// values — never a full pairwise scan. Only the resulting small
// candidate set gets the more detailed scoring pass below.

interface CorrelationIndex {
  features: Map<string, EmailFeatures>;
  byDomain: Map<string, Set<string>>;
  byUrl: Map<string, Set<string>>;
  byIp: Map<string, Set<string>>;
  byHash: Map<string, Set<string>>;
  byLookalikeTarget: Map<string, Set<string>>;
  byAsn: Map<string, Set<string>>;
  byHostingOrg: Map<string, Set<string>>;
  bySubjectNormalized: Map<string, Set<string>>;
}

function addTo(index: Map<string, Set<string>>, key: string | null, emailId: string): void {
  if (!key) return;
  const set = index.get(key);
  if (set) set.add(emailId);
  else index.set(key, new Set([emailId]));
}

export function buildCorrelationIndex(records: EmailRecord[]): CorrelationIndex {
  const index: CorrelationIndex = {
    features: new Map(),
    byDomain: new Map(),
    byUrl: new Map(),
    byIp: new Map(),
    byHash: new Map(),
    byLookalikeTarget: new Map(),
    byAsn: new Map(),
    byHostingOrg: new Map(),
    bySubjectNormalized: new Map(),
  };

  for (const record of records) {
    const f = extractFeatures(record);
    index.features.set(f.emailId, f);
    for (const d of f.domains) addTo(index.byDomain, d, f.emailId);
    for (const u of f.urls) addTo(index.byUrl, u, f.emailId);
    for (const ip of f.ips) addTo(index.byIp, ip, f.emailId);
    for (const h of f.hashes) addTo(index.byHash, h, f.emailId);
    addTo(index.byLookalikeTarget, f.senderLookalikeTarget, f.emailId);
    addTo(index.byAsn, f.asn, f.emailId);
    addTo(index.byHostingOrg, f.hostingOrg, f.emailId);
    if (f.subjectNormalized.length >= MIN_SUBJECT_LENGTH) {
      addTo(index.bySubjectNormalized, f.subjectNormalized, f.emailId);
    }
  }

  return index;
}

function candidateIdsFor(selected: EmailFeatures, index: CorrelationIndex): Set<string> {
  const candidates = new Set<string>();
  const collect = (set: Set<string> | undefined) => {
    if (!set) return;
    for (const id of set) if (id !== selected.emailId) candidates.add(id);
  };

  for (const d of selected.domains) collect(index.byDomain.get(d));
  for (const u of selected.urls) collect(index.byUrl.get(u));
  for (const ip of selected.ips) collect(index.byIp.get(ip));
  for (const h of selected.hashes) collect(index.byHash.get(h));
  if (selected.senderLookalikeTarget) collect(index.byLookalikeTarget.get(selected.senderLookalikeTarget));
  if (selected.asn) collect(index.byAsn.get(selected.asn));
  if (selected.hostingOrg) collect(index.byHostingOrg.get(selected.hostingOrg));
  if (selected.subjectNormalized.length >= MIN_SUBJECT_LENGTH) {
    collect(index.bySubjectNormalized.get(selected.subjectNormalized));
  }

  return candidates;
}

function intersect(a: Set<string>, b: Set<string>): string[] {
  const out: string[] = [];
  for (const v of a) if (b.has(v)) out.push(v);
  return out.sort();
}

// Bounded combination: 1 - Π(1 - weight_i) over distinct matched signal
// TYPES. Monotonic, never exceeds 1, and rewards independent corroborating
// signals without letting any single one dominate arbitrarily.
function combineConfidence(signals: CorrelationSignal[]): number {
  const remaining = signals.reduce((acc, s) => acc * (1 - s.weight), 1);
  const confidence = 1 - remaining;
  return Math.round(Math.min(1, Math.max(0, confidence)) * 1000) / 1000;
}

/**
 * Scores one candidate against the selected email's already-extracted
 * features — no re-reading of stored records, no expensive work beyond
 * a handful of set intersections and (only here, on a small candidate
 * set) two Levenshtein similarity checks.
 */
function scoreCandidate(selected: EmailFeatures, candidate: EmailFeatures): RelatedEmailMatch {
  const signals: CorrelationSignal[] = [];

  const sharedDomains = intersect(selected.domains, candidate.domains);
  if (sharedDomains.length > 0) {
    signals.push({ type: "SHARED_DOMAIN", values: sharedDomains, weight: SIGNAL_WEIGHT.SHARED_DOMAIN });
  }

  const sharedUrls = intersect(selected.urls, candidate.urls);
  if (sharedUrls.length > 0) {
    signals.push({ type: "SHARED_URL", values: sharedUrls, weight: SIGNAL_WEIGHT.SHARED_URL });
  }

  const sharedIps = intersect(selected.ips, candidate.ips);
  if (sharedIps.length > 0) {
    signals.push({ type: "SHARED_IP", values: sharedIps, weight: SIGNAL_WEIGHT.SHARED_IP });
  }

  const sharedHashes = intersect(selected.hashes, candidate.hashes);
  if (sharedHashes.length > 0) {
    signals.push({
      type: "SHARED_ATTACHMENT_HASH",
      values: sharedHashes,
      weight: SIGNAL_WEIGHT.SHARED_ATTACHMENT_HASH,
    });
  }

  const sharedInfra: string[] = [];
  if (selected.asn && selected.asn === candidate.asn) sharedInfra.push(`asn:${selected.asn}`);
  if (selected.hostingOrg && selected.hostingOrg === candidate.hostingOrg) {
    sharedInfra.push(`org:${selected.hostingOrg}`);
  }
  if (sharedInfra.length > 0) {
    signals.push({
      type: "SHARED_INFRASTRUCTURE",
      values: sharedInfra,
      weight: SIGNAL_WEIGHT.SHARED_INFRASTRUCTURE,
    });
  }

  // Sender-domain lookalike similarity: only meaningful when the two
  // sender domains actually differ (an exact match is already counted
  // under SHARED_DOMAIN) and both were flagged as look-alikes of the
  // SAME trusted brand target — real evidence of a coordinated
  // impersonation campaign, not a coincidence.
  if (
    selected.senderDomain &&
    candidate.senderDomain &&
    selected.senderDomain !== candidate.senderDomain &&
    selected.senderLookalikeTarget &&
    selected.senderLookalikeTarget === candidate.senderLookalikeTarget
  ) {
    signals.push({
      type: "SENDER_DOMAIN_SIMILARITY",
      values: [`both impersonate ${selected.senderLookalikeTarget}`],
      weight: SIGNAL_WEIGHT.SENDER_DOMAIN_SIMILARITY,
    });
  }

  // Subject similarity: skip trivially short subjects and only accept
  // similarity above threshold — approximates "content similarity" for
  // this MVP without loading/comparing full email bodies across the set.
  if (
    selected.subjectRaw &&
    candidate.subjectRaw &&
    selected.subjectNormalized.length >= MIN_SUBJECT_LENGTH &&
    candidate.subjectNormalized.length >= MIN_SUBJECT_LENGTH
  ) {
    const sim =
      selected.subjectNormalized === candidate.subjectNormalized
        ? 1
        : normalizedSimilarity(selected.subjectNormalized, candidate.subjectNormalized);
    if (sim >= SUBJECT_SIMILARITY_THRESHOLD) {
      signals.push({
        type: "SUBJECT_SIMILARITY",
        values: [`similarity ${Math.round(sim * 100) / 100}`],
        weight: SIGNAL_WEIGHT.SUBJECT_SIMILARITY,
      });
    }
  }

  return {
    emailId: candidate.emailId,
    confidence: combineConfidence(signals),
    signals,
  };
}

function shortHash(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 8).toUpperCase();
}

// Deterministic prototype campaign ID: derived from the single strongest,
// most-shared indicator value among the qualifying matches (ties broken
// by signal strength then value). Two different selected emails in the
// same underlying cluster resolve to the same campaignId because the
// derivation depends only on the shared evidence, not on which email
// was queried. Never implies confirmed attribution — see response wording.
function deriveCampaignId(selected: EmailFeatures, matches: RelatedEmailMatch[]): string | null {
  if (matches.length === 0) return null;

  const strongTypesInOrder: CorrelationSignalType[] = [
    "SHARED_ATTACHMENT_HASH",
    "SHARED_IP",
    "SHARED_URL",
    "SHARED_INFRASTRUCTURE",
    "SHARED_DOMAIN",
  ];

  const tally = new Map<string, number>(); // `${type}:${value}` -> match count
  for (const match of matches) {
    for (const signal of match.signals) {
      for (const value of signal.values) {
        const key = `${signal.type}:${value}`;
        tally.set(key, (tally.get(key) ?? 0) + 1);
      }
    }
  }

  let best: { key: string; count: number; typeRank: number } | null = null;
  for (const [key, count] of tally) {
    const type = key.slice(0, key.indexOf(":")) as CorrelationSignalType;
    const typeRank = strongTypesInOrder.indexOf(type);
    if (typeRank === -1) continue; // similarity-only signals never anchor a campaign id alone
    if (
      !best ||
      count > best.count ||
      (count === best.count && typeRank < best.typeRank) ||
      (count === best.count && typeRank === best.typeRank && key < best.key)
    ) {
      best = { key, count, typeRank };
    }
  }

  if (!best) return null;
  return `CMP-${shortHash(best.key)}`;
}

export function correlateEmail(selected: EmailRecord, allRecords: EmailRecord[]): RelatedEmailsResponse {
  const index = buildCorrelationIndex(allRecords);
  const selectedFeatures =
    index.features.get(selected.emailId) ?? extractFeatures(selected);

  const candidateIds = candidateIdsFor(selectedFeatures, index);

  const matches: RelatedEmailMatch[] = [];
  for (const candidateId of candidateIds) {
    const candidateFeatures = index.features.get(candidateId);
    if (!candidateFeatures) continue;
    const match = scoreCandidate(selectedFeatures, candidateFeatures);
    if (match.confidence >= MIN_RELATED_CONFIDENCE) matches.push(match);
  }

  matches.sort((a, b) => b.confidence - a.confidence || a.emailId.localeCompare(b.emailId));

  const relatedEmailIds = matches.map((m) => m.emailId);
  const confidence = matches.length > 0 ? matches[0].confidence : 0;
  const campaignId = deriveCampaignId(selectedFeatures, matches);

  const sharedIndicators = new Set<string>();
  const sharedInfrastructure = new Set<string>();
  const reasons: string[] = [];

  for (const match of matches) {
    const parts: string[] = [];
    for (const signal of match.signals) {
      const label = signal.type.toLowerCase().replace(/_/g, " ");
      parts.push(`${label} (${signal.values.join(", ")})`);
      for (const value of signal.values) {
        const tag = `${signal.type}:${value}`;
        if (signal.type === "SHARED_IP" || signal.type === "SHARED_INFRASTRUCTURE") {
          sharedInfrastructure.add(tag);
        } else {
          sharedIndicators.add(tag);
        }
      }
    }
    reasons.push(
      `Potentially related to ${match.emailId} via ${parts.join("; ")} (confidence ${match.confidence}).`
    );
  }

  if (campaignId) {
    reasons.unshift(
      `Likely Related Campaign ${campaignId}: ${relatedEmailIds.length} potentially related email(s) found based on shared evidence. This groups emails by shared indicators only — it does not confirm a threat-actor identity.`
    );
  }

  return {
    emailId: selected.emailId,
    campaignId,
    confidence,
    relatedEmailIds,
    sharedIndicators: [...sharedIndicators].sort(),
    sharedInfrastructure: [...sharedInfrastructure].sort(),
    reasons,
  };
}
