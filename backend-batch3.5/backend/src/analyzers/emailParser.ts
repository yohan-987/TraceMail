import { simpleParser, AddressObject, ParsedMail } from "mailparser";
import type { AttachmentInfo, BodyContent, EmailAddress, ParsedEmail } from "../schemas/types";
import { sha256 } from "../utils/hash";

// Headers we specifically care about preserving for forensic analysis
// in later batches (Batch 2 header/auth forensics reads these). This
// list is informational only here — its absence in a given email is
// not itself an anomaly (e.g. a benign email may lack DKIM-Signature).
export const FORENSIC_HEADERS = [
  "received",
  "authentication-results",
  "received-spf",
  "dkim-signature",
  "x-originating-ip",
  "return-path",
  "reply-to",
  "message-id",
  "x-mailer",
  "user-agent",
] as const;

function splitAddress(address: string | undefined | null): {
  localPart: string | null;
  domain: string | null;
} {
  if (!address || !address.includes("@")) return { localPart: null, domain: null };
  const atIndex = address.lastIndexOf("@");
  const localPart = address.slice(0, atIndex) || null;
  const domain = address.slice(atIndex + 1).toLowerCase() || null;
  return { localPart, domain };
}

function toEmailAddresses(addr: AddressObject | AddressObject[] | undefined): EmailAddress[] {
  if (!addr) return [];
  const groups = Array.isArray(addr) ? addr : [addr];
  const result: EmailAddress[] = [];
  for (const group of groups) {
    for (const entry of group.value ?? []) {
      const email = entry.address ? entry.address.toLowerCase() : null;
      const { localPart, domain } = splitAddress(email);
      result.push({ displayName: entry.name || null, email, localPart, domain });
    }
  }
  return result;
}

// Return-Path isn't parsed into an AddressObject by mailparser — it
// comes through as a raw header line. Parse it manually.
function parseReturnPath(rawLine: string | undefined): EmailAddress[] {
  if (!rawLine) return [];
  const valueOnly = rawLine.replace(/^return-path:\s*/i, "");
  const cleaned = valueOnly.replace(/[<>]/g, "").trim();
  if (!cleaned || !cleaned.includes("@")) return [];
  const email = cleaned.toLowerCase();
  const { localPart, domain } = splitAddress(email);
  return [{ displayName: null, email, localPart, domain }];
}

function stripHeaderPrefix(line: string): string {
  const idx = line.indexOf(":");
  return idx >= 0 ? line.slice(idx + 1).trim() : line.trim();
}

export interface ParseOutcome {
  parsed: ParsedEmail;
  warnings: string[];
}

/**
 * Parses raw .eml bytes into our ParsedEmail shape. Never throws —
 * evidence must be preserved and a record must be creatable even when
 * the email is malformed; parse failures degrade into warnings on an
 * otherwise-empty ParsedEmail rather than aborting the scan.
 */
export async function parseEmlBuffer(emailId: string, raw: Buffer): Promise<ParseOutcome> {
  const warnings: string[] = [];

  let mail: ParsedMail;
  try {
    mail = await simpleParser(raw);
  } catch (err) {
    warnings.push(`Email parsing failed: ${(err as Error).message}`);
    return {
      warnings,
      parsed: {
        emailId,
        subject: null,
        from: [],
        to: [],
        cc: [],
        bcc: [],
        replyTo: [],
        returnPath: [],
        date: null,
        messageId: null,
        headers: { normalized: {}, raw: [] },
        body: { text: null, html: null },
        attachments: [],
      },
    };
  }

  // Preserve every header line in original order, INCLUDING duplicates
  // (e.g. multiple Received hops) — critical for relay-chain
  // reconstruction in Batch 2. mailparser's headerLines gives us the
  // full raw line per header, unfolded but otherwise untouched.
  const rawHeaders: { name: string; value: string }[] = (mail.headerLines ?? []).map((h) => ({
    name: h.key,
    value: h.line,
  }));

  // Normalized map: same data, grouped by lowercase header name, with
  // duplicates collected into arrays. Values here have the "Key: "
  // prefix stripped (raw[] keeps the full original line for exactness).
  const normalized: Record<string, string | string[]> = {};
  for (const h of rawHeaders) {
    const key = h.name.toLowerCase();
    const value = stripHeaderPrefix(h.value);
    const existing = normalized[key];
    if (existing === undefined) {
      normalized[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      normalized[key] = [existing, value];
    }
  }

  const returnPathLine = rawHeaders.find((h) => h.name.toLowerCase() === "return-path")?.value;

  const attachments: AttachmentInfo[] = (mail.attachments ?? []).map((a) => ({
    filename: a.filename || "unnamed-attachment",
    mimeType: a.contentType || "application/octet-stream",
    sizeBytes: a.size ?? a.content.length,
    sha256: sha256(a.content),
  }));

  const body: BodyContent = {
    text: mail.text ?? null,
    // mail.html is `false` (not undefined) when there's no HTML part.
    html: typeof mail.html === "string" ? mail.html : null,
  };

  if (!mail.from) {
    warnings.push("No 'From' address could be parsed from this email.");
  }

  const parsed: ParsedEmail = {
    emailId,
    subject: mail.subject ?? null,
    from: toEmailAddresses(mail.from),
    to: toEmailAddresses(mail.to),
    cc: toEmailAddresses(mail.cc),
    bcc: toEmailAddresses(mail.bcc),
    replyTo: toEmailAddresses(mail.replyTo),
    returnPath: parseReturnPath(returnPathLine),
    date: mail.date ? mail.date.toISOString() : null,
    messageId: mail.messageId ?? null,
    headers: { normalized, raw: rawHeaders },
    body,
    attachments,
  };

  return { parsed, warnings };
}
