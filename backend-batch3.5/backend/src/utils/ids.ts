import { customAlphabet } from "nanoid";

// Uppercase alphanumeric, no ambiguous chars (0/O, 1/I) — easier to read
// aloud during a demo if a judge asks you to reference an ID.
const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const shortId = customAlphabet(alphabet, 6);

function todayStamp(): string {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

// emailId is the primary investigation identity (see architecture note
// in schemas/types.ts). caseId uses the same shape but is optional
// grouping metadata — never required to create or fetch an email.
export function generateEmailId(): string {
  return `EMAIL-${todayStamp()}-${shortId()}`;
}

export function generateCaseId(): string {
  return `CASE-${todayStamp()}-${shortId()}`;
}
