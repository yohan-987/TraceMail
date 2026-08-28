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

// Batch 2 fills in real values; Batch 0 only established the shape.
export interface HeaderAnalysis {
  emailId: string;
  anomalies: HeaderAnomaly[];
  receivedChain: ReceivedHop[];
  status: EvidenceStatus;
}

export interface AuthenticationAnalysis {
  emailId: string;
  spf: { result: AuthResult | "unknown"; raw: string | null };
  dkim: { result: AuthResult | "unknown"; raw: string | null };
  dmarc: { result: AuthResult | "unknown"; policy: string | null; raw: string | null };
}

export interface IOCSet {
  emailId: string;
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
  emails: string[];
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
}

export interface EmailRecord {
  emailId: string;
  caseId: string | null;
  evidence: EvidenceMeta;
  parsedEmail: ParsedEmail | null;
  headerAnalysis: HeaderAnalysis | null;
  authentication: AuthenticationAnalysis | null;
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
