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