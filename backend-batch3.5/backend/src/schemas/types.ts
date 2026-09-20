// Central type definitions — the single source of truth every batch/module
// imports from. Extend these in place as later batches add real analysis
// logic; never duplicate shape definitions in individual route files.
//
// ARCHITECTURE NOTE (Batch 0):
// emailId is the PRIMARY investigation identity. caseId is optional
// grouping metadata only. There is no backend "activeCase" or
// "activeEmail" concept — every email is independently retrievable and
// analyzable by emailId alone. Do not add code paths that require a
// caseId to exist before an email can be scanned or fetched.

export type AuthResult =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror";

export type EvidenceStatus =
  | "VERIFIED"
  | "SUSPICIOUS"
  | "MALICIOUS"
  | "INCONCLUSIVE"
  | "UNAVAILABLE";

export type RiskLevel = "low" | "moderate" | "high" | "critical";

export interface EmailAddress {
  displayName: string | null;
  email: string | null;
  localPart: string | null;
  domain: string | null;
}

export interface AttachmentInfo {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
}

export interface BodyContent {
  text: string | null;
  html: string | null; // untrusted — never rendered without sanitization
}

// --- Per-emailId analysis objects -----------------------------------
// Each carries its own emailId so these can be stored/fetched/tested
// independently of the parent EmailRecord if needed later.

export interface ParsedEmail {
  emailId: string;
  subject: string | null;
  from: EmailAddress[];
  to: EmailAddress[];
  cc: EmailAddress[];
  bcc: EmailAddress[];
  replyTo: EmailAddress[];
  returnPath: EmailAddress[];
  date: string | null;
  messageId: string | null;
  headers: {
    normalized: Record<string, string | string[]>;
    raw: { name: string; value: string }[];
  };
  body: BodyContent;
  attachments: AttachmentInfo[];
}

export type IpClassification = "PUBLIC" | "PRIVATE" | "LOOPBACK" | "LINK_LOCAL" | "INVALID";

// The five scoring buckets used everywhere risk evidence is produced —
// header forensics (Batch 2), IOC/URL/domain/content analysis (Batch 3),
// and infrastructure enrichment (Batch 4) all tag their evidence with one
// of these so the risk engine can group and combine them per category.
export type RiskCategory = "technical" | "identity" | "urlDomain" | "content" | "infrastructure";

// Where a piece of evidence came from — lets the UI (and future
// reviewers) distinguish "we directly observed this fact" from "a
// model inferred this." Batch 3's evidence is deterministic rule
// output, so it's tagged DETERMINISTIC_ANALYSIS; the other values are
// reserved for Batch 4+ (GeoIP/threat-intel -> EXTERNAL_INTELLIGENCE,
// a future classifier -> ML_ASSESSMENT, an LLM's semantic read ->
// AI_INTERPRETATION, a derived-but-not-directly-observed conclusion ->
// INFERRED). Nothing in Batch 3.5 produces those yet.
export type EvidenceProvenance =
  | "OBSERVED"
  | "DETERMINISTIC_ANALYSIS"
  | "EXTERNAL_INTELLIGENCE"
  | "ML_ASSESSMENT"
  | "AI_INTERPRETATION"
  | "INFERRED";

export interface HeaderAnomaly {
  type: string; // e.g. "reply_to_mismatch", "spf_fail"
  severity: "low" | "medium" | "high";
  message: string;
  evidence: Record<string, unknown>;
  weight: number; // risk contribution, NOT a probability — the risk engine consumes this
  category: RiskCategory;
  provenance: EvidenceProvenance;
  /**
   * Evidence-strength tag (see docs/audit/PHASE1-AUDIT.md, Finding 3).
   * "weak" = a contextual signal that is common in entirely legitimate
   * mail on its own — URL exists, percent-encoding, multiple
   * subdomains, a Return-Path/Message-ID mismatch from third-party send
   * infrastructure, ordinary urgency/call-to-action marketing copy —
   * and must not, by accumulation alone, drive a category score into
   * "high" territory. "strong" = a signal that specifically indicates
   * malicious intent (confirmed malicious reputation, credential-
   * harvesting destination, lookalike/homograph domain, auth failure,
   * malicious attachment hash, brand/authority impersonation, etc).
   * Optional: evidence producers written before this field existed
   * (domain reputation, infrastructure, ML/AI evidence) omit it, and
   * the risk engine treats an untagged item as equivalent to "strong"
   * (i.e. unrestricted) so those existing sources are unaffected.
   */
  strength?: "weak" | "strong";
}

// HeaderAnomaly's shape is deliberately general-purpose (not header-
// specific) — Batch 3's URL/domain/content analyzers reuse the exact
// same shape rather than introducing a parallel evidence type. This
// alias is just a more accurate name for code written after Batch 2.
export type RiskEvidenceItem = HeaderAnomaly;

export interface ReceivedHop {
  hop: number; // 1-based, in the order the header appears in the raw file
  fromHostname: string | null;
  fromIp: string | null;
  fromIpClassification: IpClassification | null;
  byHostname: string | null;
  timestampRaw: string | null;
  timestampIso: string | null;
  rawHeader: string;
}

// Batch 3: identifies the earliest reliable PUBLIC hop in the Received
// chain, distinct from the (unverified) claimed origin the message's own
// headers assert. Never call this "attacker location" anywhere — an
// attacker who controls their own outbound server can insert fake
// Received headers before it ever reaches genuinely public infrastructure.
export interface EarliestOriginResult {
  claimedOrigin: string | null;
  earliestReliableOrigin: string | null;
  hopIndexOfOrigin: number | null;
  relayHops: ReceivedHop[];
  routingAnomalies: string[];
  basis: "earliest_reliable_public_hop" | "no_reliable_public_hop_found";
}

// Batch 2 fills in real values; Batch 0 only established the shape.
export interface HeaderAnalysis {
  emailId: string;
  anomalies: HeaderAnomaly[];
  receivedChain: ReceivedHop[];
  earliestOrigin: EarliestOriginResult;
  status: EvidenceStatus;
}

export interface AuthenticationAnalysis {
  emailId: string;
  spf: { result: AuthResult | "unknown"; raw: string | null };
  dkim: { result: AuthResult | "unknown"; raw: string | null };
  dmarc: { result: AuthResult | "unknown"; policy: string | null; raw: string | null };
}

/**
 * Forensic-safe forwarded-email model (docs/audit/PHASE1-AUDIT.md,
 * Finding 5 / Prompt 5). Distinguishes the FORWARDER (whoever's account
 * sent the message that reached this mailbox — always `parsed.from[0]`,
 * never assumed to be the original author) from the ORIGINAL SENDER
 * (the sender represented inside a recognized forwarded-content block,
 * if one is found and reliably parseable). See forwardingAnalyzer.ts.
 */
export interface ForwardingAnalysis {
  emailId: string;
  isForwarded: boolean;
  forwarder: EmailAddress | null;
  /** "UNKNOWN" (not null/omitted) when forwarding is detected but the
   *  original sender could not be reliably parsed out of the body —
   *  labeled explicitly rather than invented (Prompt 5, requirement 5). */
  originalSender: EmailAddress | "UNKNOWN" | null;
  originalSubject: string | null;
  /** Number of separate forwarded-header blocks found. originalSender
   *  reflects only the OUTERMOST block; deeper nesting is not resolved —
   *  a count > 1 is a signal for manual review, not something scored. */
  nestedForwardCount: number;
  detectionEvidence: string[];
  confidence: "high" | "low" | "none";
}

export interface IOCSet {
  emailId: string;
  ips: string[];
  domains: string[];
  urls: string[]; // RAW, exact-string-deduplicated occurrences — preserved for forensic display (Prompt 4, req. 1/4)
  /**
   * CANONICAL indicators: raw URLs grouped by hostname (see
   * iocExtractor.ts's groupUrlsByHost, docs/audit/PHASE1-AUDIT.md
   * Finding 1 and Prompt 4). This is the "same underlying domain/IP/
   * hash/URL must not receive unlimited risk simply because it appears
   * repeatedly" model: a legitimate bulk email with 90 unique tracking-
   * parameter URLs to one host produces ONE canonical indicator here
   * (occurrenceCount: 90), not 90. `urls` above is left untouched for
   * forensic/audit display of every raw occurrence; this field is what
   * risk calculation and indicator-count summaries should prefer.
   */
  canonicalUrlIndicators: CanonicalUrlIndicator[];
  hashes: string[];
  emails: string[];
}

export interface CanonicalUrlIndicator {
  hostname: string;
  occurrenceCount: number; // how many raw URLs (from `urls` above) share this hostname
  sampleUrls: string[]; // up to 5 representative raw URLs, for forensic display without repeating all N
}

export interface URLAnalysis {
  emailId: string;
  urls: {
    url: string;
    hostname: string;
    domain: string;
    isHttps: boolean;
    urlLength: number;
    subdomainLength: number;
    pathLength: number;
    queryLength: number;
    hasIpHost: boolean;
    hasAtSymbol: boolean;
    hasEncodedCharacters: boolean;
    hasMultipleSubdomains: boolean;
    isShortened: boolean;
    riskNotes: string[];
  }[];
}

export interface DomainAnalysis {
  emailId: string;
  domains: {
    domain: string;
    tld: string | null;
    subdomain: string | null;
    hostnameLength: number;
    hyphenCount: number;
    digitCount: number;
    isPunycode: boolean;
    lookalikeOf: string | null;
    similarityScore: number | null;
  }[];
}

// Whether a category's evidence could even be evaluated — distinct from
// the SCORE itself. A category with no applicable signals (e.g. no URLs
// in this email) or no evidence source yet (e.g. GeoIP not implemented
// until Batch 4) must never be silently treated as "0 = safe" — that's
// exactly the confusion this type prevents.
export type EvidenceAvailability =
  | "AVAILABLE"
  | "NOT_APPLICABLE"
  | "UNAVAILABLE"
  | "ERROR"
  | "INCONCLUSIVE";

export interface CategoryResult {
  score: number | null; // null whenever status !== "AVAILABLE"
  status: EvidenceAvailability;
  evidence: RiskEvidenceItem[];
}

export interface RiskAssessment {
  emailId: string;
  categoryScores: {
    technical: CategoryResult;
    identity: CategoryResult;
    urlDomain: CategoryResult;
    content: CategoryResult;
    infrastructure: CategoryResult;
  } | null;
  score: number | null; // null only when EVERY category is unavailable — never coerced to 0
  level: RiskLevel | null;
  classification: string | null;
  confidence: number | null;
  // Fraction (0-1) of the five categories that were AVAILABLE when this
  // assessment was computed. Lets the UI show "this score reflects 3 of
  // 5 categories" rather than implying full-coverage confidence.
  evidenceCoverage: number | null;
}

export type MLClassification = "phishing" | "legitimate";

export interface MLAssessment {
  emailId: string;
  model: string | null;
  modelVersion: string | null;
  /** Tokenization strategy actually used by the loaded model (Prompt
   *  10's "unambiguous model/version display": MODEL / VERSION /
   *  TOKENIZATION). Sourced from the loaded model file's own
   *  metadata.tokenizer — never hardcoded. Null when the model
   *  couldn't be described (no predictor loaded, or describe() failed). */
  tokenizer: string | null;
  classification: MLClassification | null;
  /** Model score in [0, 1] — not a calibrated probability. */
  probability: number | null;
  status: EvidenceAvailability;
}

export interface IntelligenceAssessment {
  emailId: string;
  status: EvidenceAvailability;
}

export interface AIAssessment {
  emailId: string;
  status: EvidenceAvailability;
  phishingIntent: number | null;
  credentialHarvesting: number | null;
  financialFraud: number | null;
  impersonation: number | null;
  socialEngineering: number | null;
  malwareDelivery: number | null;
  /** Qualitative concern level the model assigned — for DISPLAY as a
   *  "Semantic Content Assessment" alongside, never in place of, the
   *  deterministic canonical risk level (Prompt 6). Never drives
   *  scoring directly; see aiAssessment.ts's groundedness gating. */
  concernLevel: "none" | "low" | "medium" | "high" | null;
  /** Up to 5 short reasons, each an OBSERVATION the model distinguished
   *  from its security significance (Prompt 6, requirement 2) — not a
   *  restatement of raw evidence, and not one entry per near-duplicate
   *  URL (the model is only ever shown canonical, host-grouped URL
   *  indicators — see buildLlmUserPayload — so it structurally cannot
   *  produce 10 copies of the same URL finding). */
  topReasons: string[];
  /** A benign, non-malicious explanation for the same observations,
   *  when one plausibly applies (e.g. "marketing tracking links are
   *  routine for promotional senders") — null when none applies, never
   *  fabricated to seem balanced. */
  benignExplanation: string | null;
  confidence: "low" | "medium" | "high" | null;
  attackType: string | null;
  summary: string | null;
  recommendedActions: string[];
  /** 0–100 weighted blend of the validated intent scores. */
  aiContentScore: number | null;
  provenance: EvidenceProvenance;
}

export interface GeoIpRecord {
  ip: string;
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  isp: string | null;
  asn: string | null;
  organization: string | null;
  hosting: string | null;
  status: EvidenceAvailability;
}

export interface DomainIntelligenceRecord {
  domain: string;
  resolvedIps: string[] | null;
  mxHosts: string[] | null;
  registrar: string | null;
  domainAgeDays: number | null;
  hostingOrganization: string | null;
  status: EvidenceAvailability;
}

export interface InfrastructureAssessment {
  emailId: string;
  /** Primary public candidate IP, if any. Not an attacker identity. */
  candidateIp: string | null;
  country: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  asn: string | null;
  confidence: number | null;
  status: EvidenceAvailability;
  /** GeoIP rows for public candidate IPs only. */
  ipIntelligence: GeoIpRecord[];
  domainIntelligence: DomainIntelligenceRecord[];
  /** Explicit reminder: enrichment describes probable infrastructure, not attacker location. */
  interpretation: "probable_infrastructure";
}

export interface ForensicReport {
  emailId: string;
  generatedAt: string;
  htmlAvailable: boolean;
}

// Derived infrastructure graph for one emailId (Batch 5A). Built on
// demand from the stored EmailRecord — never a second database.
export type InfrastructureGraphNodeType =
  | "EMAIL"
  | "EMAIL_ADDRESS"
  | "DOMAIN"
  | "URL"
  | "IP"
  | "ASN"
  | "ORGANIZATION"
  | "GEOLOCATION";

export type GraphProvenance =
  | "OBSERVED"
  | "DETERMINISTIC_ANALYSIS"
  | "EXTERNAL_INTELLIGENCE"
  | "INFERRED";

export interface InfrastructureGraphNode {
  id: string;
  type: InfrastructureGraphNodeType;
  label: string;
  status?: string;
  /** Prompt 10 (graph "suspicious-only filtering"). A purely DERIVED
   *  display flag for the relationship graph's filter toggle — reads
   *  already-computed analysis results (domainAnalyzer.ts's
   *  lookalikeOf, urlAnalyzer.ts's per-URL structural features) rather
   *  than computing anything new, and contributes NOTHING to risk
   *  scoring. Omitted (not `false`) when not applicable to this node
   *  type, so its absence never reads as "confirmed clean" — only
   *  DOMAIN/URL/IP nodes ever set it explicitly. See
   *  infrastructureGraph.ts for exactly which existing evidence each
   *  node type checks. */
  suspicious?: boolean;
  metadata?: Record<string, unknown>;
}

export interface InfrastructureGraphEdge {
  source: string;
  target: string;
  relationship: string;
  provenance: GraphProvenance;
  evidence?: string[];
}

export interface InfrastructureGraph {
  nodes: InfrastructureGraphNode[];
  edges: InfrastructureGraphEdge[];
}

// --- Top-level record -------------------------------------------------

export interface EvidenceMeta {
  filename: string;
  sha256: string;
  fileSizeBytes: number;
  createdAt: string; // ISO timestamp
  storagePath: string; // relative path under data/emails/<emailId>/
  // Batch 1 (Gmail): which ingestion path produced these bytes. Purely
  // descriptive — the rest of the pipeline never branches on this, so
  // an upload and a Gmail-sourced email get an identical analysis.
  // Optional so pre-Gmail stored records (with no field at all) still
  // parse correctly.
  source?: "upload" | "gmail";
  // Present only when source is "gmail" — the originating Gmail
  // message ID, kept for future dedupe/traceability.
  sourceMessageId?: string;
}

export interface EmailRecord {
  emailId: string;
  caseId: string | null;
  evidence: EvidenceMeta;
  parsedEmail: ParsedEmail | null;
  headerAnalysis: HeaderAnalysis | null;
  authentication: AuthenticationAnalysis | null;
  // Optional (not `| null`) so records stored before Prompt 5 existed
  // still parse correctly with this field simply absent rather than
  // requiring a migration.
  forwarding?: ForwardingAnalysis | null;
  iocs: IOCSet | null;
  urlAnalysis: URLAnalysis | null;
  domainAnalysis: DomainAnalysis | null;
  risk: RiskAssessment | null;
  aiAssessment: AIAssessment | null;
  infrastructure: InfrastructureAssessment | null;
  report: ForensicReport | null;
  // Every RiskEvidenceItem that contributed to `risk` — header anomalies
  // plus URL/domain/content evidence — in one flat list. This is the
  // single source the "Why flagged?" UI panel renders directly.
  explanations: RiskEvidenceItem[];
  warnings: string[];
  // Batch 4 fills these with explicit availability statuses — never
  // fabricated intel. When a provider is missing they are still present
  // with status UNAVAILABLE rather than omitted.
  mlAssessment?: MLAssessment | null;
  intelligenceAssessment?: IntelligenceAssessment | null;
}

// Lightweight shape for GET /emails table listing — avoids shipping
// full parsed bodies/headers when only a table row is needed.
// Derived from stored EmailRecord; never a second dataset.
export interface EmailSummary {
  emailId: string;
  caseId: string | null;
  filename: string;
  sender: string | null;
  senderDomain: string | null;
  recipient: string | null;
  subject: string | null;
  threatScore: number | null;
  classification: string | null;
  /** Table/filter status — the stored risk level (low/moderate/high/critical). */
  status: RiskLevel | null;
  riskLevel: RiskLevel | null;
  date: string | null;
  /** Useful stored analysis availability/status, not a live re-check. */
  analysisStatus: string | null;
  /** Scan time — used as a date fallback and for deterministic sort ties. */
  createdAt: string;
  /** @deprecated alias of senderDomain — kept so older list clients still work. */
  fromDomain: string | null;
  /** @deprecated alias of threatScore */
  riskScore: number | null;
}

export interface EmailListPagination {
  total: number;
  limit: number;
  offset: number;
}

export interface EmailListResponse {
  items: EmailSummary[];
  pagination: EmailListPagination;
}

export type EmailListSort = "date" | "threatScore";

export interface EmailListQuery {
  limit: number;
  offset: number;
  search: string | null;
  status: RiskLevel | null;
  classification: string | null;
  /** Exact caseId, or null to request emails with no case, or undefined for any. */
  caseId: string | null | undefined;
  /** When true, only emails that already have a caseId. Ignored if caseId is set. */
  hasCaseOnly: boolean;
  sort: EmailListSort;
}

// --- Related-email / campaign correlation (Batch 5B) -------------------
// Derived on demand from stored EmailRecords — same "no second dataset"
// rule as the Batch 5A infrastructure graph. Never implies confirmed
// threat-actor attribution; campaignId is a deterministic prototype
// grouping label only.
export type CorrelationSignalType =
  | "SHARED_DOMAIN"
  | "SHARED_URL"
  | "SHARED_IP"
  | "SHARED_ATTACHMENT_HASH"
  | "SHARED_INFRASTRUCTURE"
  | "SENDER_DOMAIN_SIMILARITY"
  | "SUBJECT_SIMILARITY";

export interface CorrelationSignal {
  type: CorrelationSignalType;
  /** The shared indicator value, or a short description for similarity signals. */
  values: string[];
  /** This signal type's fixed contribution toward confidence — see correlation.ts. */
  weight: number;
}

export interface RelatedEmailMatch {
  emailId: string;
  confidence: number; // bounded 0-1
  signals: CorrelationSignal[];
}

export interface RelatedEmailsResponse {
  emailId: string;
  campaignId: string | null;
  confidence: number; // bounded 0-1; strongest related match, 0 if none
  relatedEmailIds: string[];
  sharedIndicators: string[];
  sharedInfrastructure: string[];
  reasons: string[];
}

// --- Recommended investigator actions (Batch 5C) ------------------------
// Derived on demand from stored risk/domain/infrastructure/correlation
// results — advisory only. The backend never executes quarantine, block,
// contact, or firewall actions; these are suggestions for a human
// investigator, each required to cite the stored evidence it rests on.
export type RecommendedActionType =
  | "QUARANTINE_EMAIL"
  | "REVIEW_BLOCK_DOMAIN"
  | "WARN_RECIPIENT"
  | "REVIEW_RELATED_EMAILS"
  | "INVESTIGATE_SOURCE_INFRASTRUCTURE"
  | "COLLECT_ADDITIONAL_EVIDENCE";

export type RecommendationPriority = "low" | "medium" | "high" | "critical";

export interface Recommendation {
  action: RecommendedActionType;
  priority: RecommendationPriority;
  reason: string;
  /** Short, human-readable references to the specific stored evidence this rests on — never invented. */
  supportingEvidence: string[];
}

export interface ScanAcceptedResponse {
  emailId: string;
  caseId: string | null;
  filename: string;
  sha256: string;
  fileSize: number;
  status: "accepted";
  warnings: string[];
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
  };
}
