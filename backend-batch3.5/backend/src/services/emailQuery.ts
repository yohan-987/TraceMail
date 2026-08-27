import type {
  EmailListQuery,
  EmailListResponse,
  EmailListSort,
  EmailSummary,
  RiskLevel,
} from "../schemas/types";
import { Errors } from "../utils/apiError";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const RISK_LEVELS = new Set<RiskLevel>(["low", "moderate", "high", "critical"]);
const SORTS = new Set<EmailListSort>(["date", "threatScore"]);

type QueryValue = string | string[] | undefined;

function asSingle(value: QueryValue): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function parseNonNegativeInt(raw: string | undefined, fallback: number, field: string): number {
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d+$/.test(raw)) {
    throw Errors.invalidPagination(`${field} must be a non-negative integer.`);
  }
  const n = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw Errors.invalidPagination(`${field} must be a non-negative integer.`);
  }
  return n;
}

/**
 * Parse GET /emails query params. Unknown filter/sort/pagination values
 * fail with INVALID_FILTER / INVALID_PAGINATION rather than being ignored.
 *
 * caseId:
 *   omitted            → any email
 *   none | null | ""   → emails with no caseId
 *   CASE-004           → exact caseId match
 */
export function parseEmailListQuery(query: Record<string, QueryValue>): EmailListQuery {
  const limit = parseNonNegativeInt(asSingle(query.limit), DEFAULT_LIMIT, "limit");
  const offset = parseNonNegativeInt(asSingle(query.offset), 0, "offset");
  if (limit < 1) {
    throw Errors.invalidPagination("limit must be at least 1.");
  }
  if (limit > MAX_LIMIT) {
    throw Errors.invalidPagination(`limit cannot exceed ${MAX_LIMIT}.`);
  }

  const searchRaw = asSingle(query.search);
  const search = searchRaw && searchRaw.trim() !== "" ? searchRaw.trim() : null;

  const statusRaw = asSingle(query.status);
  let status: RiskLevel | null = null;
  if (statusRaw !== undefined && statusRaw.trim() !== "") {
    const normalized = statusRaw.trim().toLowerCase() as RiskLevel;
    if (!RISK_LEVELS.has(normalized)) {
      throw Errors.invalidFilter(
        "status must be one of: low, moderate, high, critical."
      );
    }
    status = normalized;
  }

  const classificationRaw = asSingle(query.classification);
  let classification: string | null = null;
  if (classificationRaw !== undefined && classificationRaw.trim() !== "") {
    const trimmed = classificationRaw.trim().toLowerCase();
    if (!/^[a-z0-9_-]+$/.test(trimmed)) {
      throw Errors.invalidFilter("classification contains invalid characters.");
    }
    classification = trimmed;
  }

  let caseId: string | null | undefined = undefined;
  let hasCaseOnly = false;

  const hasCaseRaw = asSingle(query.hasCase);
  if (hasCaseRaw !== undefined && hasCaseRaw !== "") {
    const v = hasCaseRaw.trim().toLowerCase();
    if (v === "false" || v === "0" || v === "no") {
      caseId = null;
    } else if (v === "true" || v === "1" || v === "yes") {
      hasCaseOnly = true;
    } else {
      throw Errors.invalidFilter("hasCase must be true or false.");
    }
  }

  const caseIdRaw = asSingle(query.caseId);
  if (caseIdRaw !== undefined) {
    const trimmed = caseIdRaw.trim();
    const lower = trimmed.toLowerCase();
    if (trimmed === "" || lower === "none" || lower === "null") {
      caseId = null;
      hasCaseOnly = false;
    } else {
      caseId = trimmed;
      hasCaseOnly = false;
    }
  }

  const sortRaw = asSingle(query.sort);
  let sort: EmailListSort = "date";
  if (sortRaw !== undefined && sortRaw.trim() !== "") {
    const normalized = sortRaw.trim() as EmailListSort;
    if (!SORTS.has(normalized)) {
      throw Errors.invalidFilter("sort must be one of: date, threatScore.");
    }
    sort = normalized;
  }

  return { limit, offset, search, status, classification, caseId, hasCaseOnly, sort };
}

function matchesSearch(row: EmailSummary, needle: string): boolean {
  const n = needle.toLowerCase();
  const fields = [
    row.sender,
    row.senderDomain,
    row.subject,
    row.recipient,
    row.emailId,
    row.caseId,
  ];
  return fields.some((f) => f != null && f.toLowerCase().includes(n));
}

function compareRows(a: EmailSummary, b: EmailSummary, sort: EmailListSort): number {
  let c = 0;
  if (sort === "threatScore") {
    const as = a.threatScore ?? -1;
    const bs = b.threatScore ?? -1;
    c = bs - as; // highest first
  } else {
    const ad = a.date ?? a.createdAt;
    const bd = b.date ?? b.createdAt;
    c = bd.localeCompare(ad); // newest first
  }
  if (c === 0) c = b.emailId.localeCompare(a.emailId);
  return c;
}

export function applyEmailListQuery(rows: EmailSummary[], q: EmailListQuery): EmailListResponse {
  let filtered = rows;

  if (q.search) {
    filtered = filtered.filter((row) => matchesSearch(row, q.search as string));
  }
  if (q.status) {
    filtered = filtered.filter((row) => row.status === q.status);
  }
  if (q.classification) {
    filtered = filtered.filter(
      (row) => (row.classification ?? "").toLowerCase() === q.classification
    );
  }
  if (q.caseId === null) {
    filtered = filtered.filter((row) => row.caseId == null);
  } else if (typeof q.caseId === "string") {
    filtered = filtered.filter((row) => row.caseId === q.caseId);
  } else if (q.hasCaseOnly) {
    filtered = filtered.filter((row) => row.caseId != null && row.caseId !== "");
  }

  const sorted = [...filtered].sort((a, b) => compareRows(a, b, q.sort));
  const total = sorted.length;
  const items = sorted.slice(q.offset, q.offset + q.limit);

  return {
    items,
    pagination: { total, limit: q.limit, offset: q.offset },
  };
}
