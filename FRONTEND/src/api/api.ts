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