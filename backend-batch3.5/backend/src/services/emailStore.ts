import { promises as fs } from "fs";
import path from "path";
import { Errors } from "../utils/apiError";
import type { EmailAddress, EmailRecord, EmailSummary } from "../schemas/types";
import { assessConsistency, applyConsistencyOverride } from "../analyzers/evidenceConsistency";

// Layout (Batch 1 spec section 5):
//   data/emails/<emailId>/original.eml   — exact uploaded bytes, never modified
//   data/emails/<emailId>/parsed.json    — the full EmailRecord (parsed
//                                          email + every analysis slot
//                                          later batches fill in)
//   data/emails/<emailId>/summary.json   — lightweight list-row projection of
//                                          the same EmailRecord (Batch 5).
//                                          Not a second dataset.
//
// emailId is always our own generated ID (ids.ts), never taken raw from
// user input, so directory names can't be used for path traversal —
// still sanitized defensively below.

const DEFAULT_DATA_DIR = path.join(__dirname, "..", "..", "data", "emails");

function dataDir(): string {
  // EMAIL_DATA_DIR lets tests isolate storage without touching production data.
  if (process.env.EMAIL_DATA_DIR && process.env.EMAIL_DATA_DIR.trim() !== "") {
    return path.resolve(process.env.EMAIL_DATA_DIR);
  }
  return DEFAULT_DATA_DIR;
}

function safeId(emailId: string): string {
  return emailId.replace(/[^A-Za-z0-9-]/g, "");
}

function emailDir(emailId: string): string {
  return path.join(dataDir(), safeId(emailId));
}

function originalEmlPath(emailId: string): string {
  return path.join(emailDir(emailId), "original.eml");
}

function parsedJsonPath(emailId: string): string {
  return path.join(emailDir(emailId), "parsed.json");
}

function summaryJsonPath(emailId: string): string {
  return path.join(emailDir(emailId), "summary.json");
}

function formatAddress(addr: EmailAddress | undefined): string | null {
  if (!addr) return null;
  return addr.email ?? addr.displayName ?? null;
}

function analysisStatusFrom(record: EmailRecord): string | null {
  if (record.aiAssessment?.status && record.aiAssessment.status !== "UNAVAILABLE") {
    return record.aiAssessment.status;
  }
  if (record.mlAssessment?.status && record.mlAssessment.status !== "UNAVAILABLE") {
    return record.mlAssessment.status;
  }
  if (record.infrastructure?.status && record.infrastructure.status !== "UNAVAILABLE") {
    return record.infrastructure.status;
  }
  return record.headerAnalysis?.status ?? null;
}

/** Project a stored EmailRecord into a table row. Does not re-analyze
 *  in the sense of ML/LLM/GeoIP/DNS — but DOES apply the same evidence-
 *  consistency override routes/emails.ts's GET /emails/:emailId applies,
 *  via applyConsistencyOverride, so list rows never show a different
 *  classification/level than the detail view for the same email. */
export function toEmailSummary(record: EmailRecord): EmailSummary {
  const from = record.parsedEmail?.from?.[0];
  const to = record.parsedEmail?.to?.[0];
  const senderDomain = from?.domain ?? null;
  const threatScore = record.risk?.score ?? null;

  const consistency = record.risk
    ? assessConsistency({
        risk: record.risk,
        authentication: record.authentication ?? null,
        aiAssessment: record.aiAssessment ?? null,
        urlDomainCategory: record.risk.categoryScores?.urlDomain ?? null,
      })
    : null;
  const { classification, level: riskLevel } = applyConsistencyOverride(record.risk, consistency);

  return {
    emailId: record.emailId,
    caseId: record.caseId,
    filename: record.evidence.filename,
    sender: formatAddress(from),
    senderDomain,
    recipient: formatAddress(to),
    subject: record.parsedEmail?.subject ?? null,
    threatScore,
    classification,
    status: riskLevel,
    riskLevel,
    date: record.parsedEmail?.date ?? record.evidence.createdAt,
    analysisStatus: analysisStatusFrom(record),
    createdAt: record.evidence.createdAt,
    fromDomain: senderDomain,
    riskScore: threatScore,
  };
}

export async function saveOriginalEml(emailId: string, raw: Buffer): Promise<string> {
  const dir = emailDir(emailId);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(originalEmlPath(emailId), raw);
  // Relative path — stored in EvidenceMeta.storagePath for the record;
  // absolute paths shouldn't leak into API responses.
  return path.join("data", "emails", safeId(emailId), "original.eml");
}

export async function saveEmailRecord(record: EmailRecord): Promise<void> {
  const dir = emailDir(record.emailId);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(parsedJsonPath(record.emailId), JSON.stringify(record, null, 2), "utf-8");
  await fs.writeFile(
    summaryJsonPath(record.emailId),
    JSON.stringify(toEmailSummary(record), null, 2),
    "utf-8"
  );
}

export async function getEmailRecord(emailId: string): Promise<EmailRecord | null> {
  try {
    const raw = await fs.readFile(parsedJsonPath(emailId), "utf-8");
    try {
      return JSON.parse(raw) as EmailRecord;
    } catch {
      // Batch 7 hardening: a corrupted/truncated stored record is a
      // server-side storage problem — surface it as a controlled 500,
      // never let the raw JSON.parse SyntaxError reach the client.
      throw Errors.recordUnreadable(emailId);
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

async function readSummary(emailId: string): Promise<EmailSummary | null> {
  // Always derive live from the full record — never trust the cached
  // summary.json file written by saveEmailRecord(). That file is
  // written once, at ingestion time, before any live-computed override
  // (e.g. the evidence-consistency engine) has run — trusting it here
  // was the exact root cause of list rows showing a stale risk level
  // after AI Investigation's detail view was already showing the
  // corrected one. toEmailSummary is a cheap, pure projection (no I/O,
  // no re-running ML/LLM/GeoIP/DNS) — there's no meaningful cost to
  // always recomputing it from parsed.json instead of reading a copy
  // that can drift out of sync with it.
  const record = await getEmailRecord(emailId);
  if (!record) return null;
  return toEmailSummary(record);
}

export async function listEmailSummaries(): Promise<EmailSummary[]> {
  await fs.mkdir(dataDir(), { recursive: true });
  const entries = await fs.readdir(dataDir(), { withFileTypes: true });
  const emailDirs = entries.filter((e) => e.isDirectory());

  const summaries: EmailSummary[] = [];
  for (const dirEntry of emailDirs) {
    const summary = await readSummary(dirEntry.name);
    if (!summary) continue;
    summaries.push(summary);
  }

  summaries.sort((a, b) => {
    const byDate = b.createdAt.localeCompare(a.createdAt);
    return byDate !== 0 ? byDate : b.emailId.localeCompare(a.emailId);
  });
  return summaries;
}

// Full stored records for every email — used by Batch 5B correlation to
// build an in-memory indicator index. This is an O(n) directory read,
// not a second dataset: it just replays getEmailRecord() across every
// stored emailId. Callers must not use this in a loop per-candidate;
// build one index per request and reuse it (see analyzers/correlation.ts).
export async function listAllEmailRecords(): Promise<EmailRecord[]> {
  await fs.mkdir(dataDir(), { recursive: true });
  const entries = await fs.readdir(dataDir(), { withFileTypes: true });
  const emailDirs = entries.filter((e) => e.isDirectory());

  const records: EmailRecord[] = [];
  for (const dirEntry of emailDirs) {
    const record = await getEmailRecord(dirEntry.name);
    if (record) records.push(record);
  }
  return records;
}

/** Strip filesystem paths before sending a stored record to the client. */
export function toPublicEmailRecord(record: EmailRecord): Record<string, unknown> {
  const { storagePath: _storagePath, ...evidence } = record.evidence;
  return {
    ...record,
    evidence,
    // Frontend-facing aliases for the same stored objects — no new values.
    email: record.parsedEmail,
    headers: record.headerAnalysis,
    urlDomainAnalysis: {
      emailId: record.emailId,
      urlAnalysis: record.urlAnalysis,
      domainAnalysis: record.domainAnalysis,
    },
  };
}
