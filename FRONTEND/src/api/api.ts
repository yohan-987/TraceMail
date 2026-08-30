export interface ApiEmailSummary {
  emailId: string;
  caseId: string | null;
  sender: string;
  senderDomain?: string;
  recipient: string;
  subject: string;
  threatScore: number;
  classification: string;
  status: string;
  riskLevel?: string;
  date: string;
  analysisStatus?: string;
}

// The shape returned by GET /api/v1/emails/:emailId — the full stored
// EmailRecord (Batch 1-4) plus `email`/`headers`/`urlDomainAnalysis`
// aliases and Batch 5C's `recommendations` (see backend
// toPublicEmailRecord + the GET /:emailId route handler). This is
// deliberately NOT the same flat shape as ApiEmailSummary (the list
// endpoint) — nested under `risk`/`mlAssessment`/`aiAssessment` instead
// of flattened to top-level fields. emailMapper.ts reads from whichever
// of the two shapes it's actually given.
export interface ApiRecommendation {
  action: string;
  priority: string;
  reason: string;
  supportingEvidence: string[];
}

export interface ApiEmailDetail {
  emailId: string;
  caseId: string | null;
  email?: {
    subject?: string | null;
    from?: Array<{ email?: string | null; displayName?: string | null }>;
    to?: Array<{ email?: string | null }>;
    date?: string | null;
  } | null;
  authentication?: {
    spf?: { result?: string } | null;
    dkim?: { result?: string } | null;
    dmarc?: { result?: string } | null;
  } | null;
  risk?: {
    score?: number | null;
    level?: string | null;
    classification?: string | null;
  } | null;
  mlAssessment?: {
    probability?: number | null;
    status?: string;
  } | null;
  aiAssessment?: {
    summary?: string | null;
    attackType?: string | null;
    status?: string;
  } | null;
  explanations?: Array<{ message: string }>;
  recommendations?: ApiRecommendation[];
}

export interface ApiEmailListResponse {
  items: ApiEmailSummary[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

export async function getEmails(
  params: {
    search?: string;
    status?: string;
    classification?: string;
    caseId?: string;
    limit?: number;
    offset?: number;
    sort?: "date" | "threatScore";
  } = {}
): Promise<ApiEmailListResponse> {
  const query = new URLSearchParams();

  if (params.search) query.set("search", params.search);
  if (params.status) query.set("status", params.status);
  if (params.classification) {
    query.set("classification", params.classification);
  }
  if (params.caseId) query.set("caseId", params.caseId);
  if (params.limit !== undefined) {
    query.set("limit", String(params.limit));
  }
  if (params.offset !== undefined) {
    query.set("offset", String(params.offset));
  }
  if (params.sort) query.set("sort", params.sort);

  const queryString = query.toString();
  const url = `/api/v1/emails${queryString ? `?${queryString}` : ""}`;

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to load emails: ${response.status}`);
  }

  return response.json();
}

export async function getEmail(emailId: string) {
  // Defensive shared-layer guard: never let a malformed caller (undefined,
  // null, empty string, or an accidentally-stringified object) reach the
  // network as `/api/v1/emails/undefined` or similar. Fail fast and
  // explicitly instead, so callers' existing .catch() handlers surface a
  // clear error rather than a confusing 404.
  if (typeof emailId !== "string" || emailId.trim() === "") {
    throw new Error(
      `getEmail requires a non-empty emailId string, received: ${JSON.stringify(emailId)}`
    );
  }

  const response = await fetch(
    `/api/v1/emails/${encodeURIComponent(emailId)}`
  );

  if (!response.ok) {
    throw new Error(`Failed to load email: ${response.status}`);
  }

  return response.json();
}

// The shape returned by GET /api/v1/emails/:emailId/report (Batch 6).
// Mirrors backend src/analyzers/reportBuilder.ts's ForensicReportContent
// exactly — kept as its own type (not reused from ApiEmailDetail) since
// the report is a distinct, purpose-built projection, not the raw
// stored record.
export interface ApiForensicReport {
  emailId: string;
  generatedAt: string;
  caseInformation: { emailId: string; caseId: string | null; filename: string; generatedAt: string };
  evidenceIntegrity: {
    sha256: string;
    fileSizeBytes: number;
    collectedAt: string;
    storagePath: string;
    note: string;
  };
  emailMetadata: {
    subject: string | null;
    from: Array<{ displayName: string | null; email: string; localPart: string; domain: string }>;
    to: Array<{ displayName: string | null; email: string; localPart: string; domain: string }>;
    date: string | null;
    messageId: string | null;
    attachmentCount: number;
    status: "AVAILABLE" | "UNAVAILABLE";
  };
  authentication: {
    spf: { result: string; raw: string | null } | null;
    dkim: { result: string; raw: string | null } | null;
    dmarc: { result: string; policy: string | null; raw: string | null } | null;
    status: "AVAILABLE" | "UNAVAILABLE";
  };
  headerForensics: {
    status: string;
    anomalyCount: number;
    anomalies: { type: string; severity: string; message: string; provenance: string }[];
    receivedHopCount: number;
    receivedChain: {
      hop: number;
      fromHostname: string | null;
      fromIp: string | null;
      byHostname: string | null;
      timestampIso: string | null;
    }[];
  };
  threatAssessment: {
    score: number | null;
    level: string | null;
    classification: string | null;
    confidence: number | null;
    evidenceCoverage: number | null;
    categoryScores: Record<string, { score: number | null; status: string }> | null;
    status: "AVAILABLE" | "INSUFFICIENT_EVIDENCE";
  };
  iocs: {
    ips: string[];
    domains: string[];
    urls: string[];
    hashes: string[];
    emails: string[];
    status: "AVAILABLE" | "UNAVAILABLE";
  };
  urlDomainAnalysis: {
    urls: { url: string; hostname: string; riskNotes: string[] }[];
    domains: { domain: string; lookalikeOf: string | null; similarityScore: number | null }[];
    status: "AVAILABLE" | "NOT_APPLICABLE" | "UNAVAILABLE";
  };
  infrastructure: {
    candidateIp: string | null;
    country: string | null;
    region: string | null;
    city: string | null;
    isp: string | null;
    asn: string | null;
    confidence: number | null;
    status: string;
    interpretation: string | null;
  } | null;
  mlAiAssessment: {
    ml: {
      model: string | null;
      modelVersion: string | null;
      classification: string | null;
      probability: number | null;
      status: string;
    } | null;
    ai: {
      status: string;
      attackType: string | null;
      summary: string | null;
      phishingIntent: number | null;
      credentialHarvesting: number | null;
      financialFraud: number | null;
      impersonation: number | null;
      socialEngineering: number | null;
      malwareDelivery: number | null;
      aiContentScore: number | null;
      provenance: string;
    } | null;
  };
  whyFlagged: { type: string; severity: string; category: string; message: string; provenance: string; weight: number }[];
  recommendedActions: ApiRecommendation[];
  relatedCampaign: {
    campaignId: string | null;
    confidence: number;
    relatedEmailIds: string[];
    sharedIndicators: string[];
    sharedInfrastructure: string[];
    reasons: string[];
    available: boolean;
  };
  limitations: string[];
}

// The shape returned by GET /api/v1/emails/:emailId/related (Batch 5B).
export interface ApiRelatedEmails {
  emailId: string;
  campaignId: string | null;
  confidence: number;
  relatedEmailIds: string[];
  sharedIndicators: string[];
  sharedInfrastructure: string[];
  reasons: string[];
}

export async function getRelatedEmails(emailId: string): Promise<ApiRelatedEmails> {
  if (typeof emailId !== "string" || emailId.trim() === "") {
    throw new Error(
      `getRelatedEmails requires a non-empty emailId string, received: ${JSON.stringify(emailId)}`
    );
  }

  const response = await fetch(`/api/v1/emails/${encodeURIComponent(emailId)}/related`);

  if (!response.ok) {
    throw new Error(`Failed to load related emails: ${response.status}`);
  }

  return response.json();
}

export async function getEmailReport(emailId: string): Promise<ApiForensicReport> {
  if (typeof emailId !== "string" || emailId.trim() === "") {
    throw new Error(
      `getEmailReport requires a non-empty emailId string, received: ${JSON.stringify(emailId)}`
    );
  }

  const response = await fetch(`/api/v1/emails/${encodeURIComponent(emailId)}/report`);

  if (!response.ok) {
    throw new Error(`Failed to load report: ${response.status}`);
  }

  return response.json();
}

export async function scanEmail(file: File) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/api/v1/emails/scan", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    throw new Error(`Scan failed: ${response.status}`);
  }

  return response.json();
}