import type { ParsedEmail, ForwardingAnalysis, EmailAddress } from "../schemas/types";

/**
 * Forensic-safe forwarded-email detection (docs/audit/PHASE1-AUDIT.md,
 * Finding 5; Prompt 5). Distinguishes:
 *
 *   OUTER/RECEIVING MESSAGE — the message that actually reached this
 *   mailbox. Read exactly as every other analyzer already reads it
 *   (parsed.from, parsed.messageId, etc.) — untouched by this file.
 *
 *   FORWARDER — whoever's account sent that outer message, i.e.
 *   `parsed.from[0]`. Surfaced explicitly here rather than left
 *   implicit, so downstream consumers say "forwarded by" instead of
 *   quietly treating the forwarder as the message's author.
 *
 *   ORIGINAL SENDER — the sender represented INSIDE a recognized
 *   forwarded-content header block, if one is found and its "From:"
 *   line is parseable. Never assumed to be the forwarder (requirement
 *   2); labeled "UNKNOWN" rather than invented when it can't be
 *   reliably extracted (requirement 5).
 *
 *   ORIGINAL MESSAGE — the forwarded content itself. Not separately
 *   re-parsed or re-analyzed here: headerForensics/urlAnalyzer/
 *   contentHeuristics continue to run against the whole body exactly as
 *   before. This function only detects and labels; it does not change
 *   what evidence those analyzers produce or how risk is scored
 *   (requirement 3 — forwarding is never itself risk evidence, so this
 *   function returns descriptive metadata only, no RiskEvidenceItems).
 *
 * Authentication note (requirement 7): SPF/DKIM/DMARC are validated by
 * mail infrastructure against whoever actually transmitted THIS
 * message — for a true client-side forward (Gmail/Outlook/Apple Mail
 * "Forward" button), that is genuinely the forwarder's own send, not
 * the original sender's. headerForensics.ts's auth checks are already
 * correctly scoped to the outer message on that basis and are NOT
 * changed here; this analyzer's `isForwarded` flag exists so a report/
 * UI can caveat the displayed auth section ("reflects the forwarding
 * account's send, not the original sender") rather than silently
 * implying otherwise.
 */

const FORWARD_SUBJECT_RE = /^\s*(fwd?|fw)\s*:\s*/i;

// Recognized forwarded-content header block openers. Each pattern is
// global so a single email's full body can be scanned for every
// occurrence (nested forwarding produces more than one).
const FORWARD_BLOCK_MARKERS: { name: string; pattern: RegExp }[] = [
  { name: "gmail_forward_block", pattern: /-{2,}\s*forwarded message\s*-{2,}/gi },
  { name: "apple_mail_forward_block", pattern: /^\s*begin forwarded message\s*:?\s*$/gim },
  { name: "outlook_forward_block", pattern: /-{2,}\s*original message\s*-{2,}/gi },
];

const FROM_LINE_RE = /^\s*from\s*:\s*(.+)$/im;
const SUBJECT_LINE_RE = /^\s*subject\s*:\s*(.+)$/im;

// "Display Name <email@domain>" or a bare email address.
const ADDRESS_RE = /(?:"?([^"<]*)"?\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?/;

// How far past a detected block opener to look for its From:/Subject:
// lines — bounded so a very long forwarded thread can't cause this to
// scan (or misattribute a match from) the entire remaining body.
const BLOCK_SCAN_WINDOW = 2000;

function parseAddressLine(line: string): EmailAddress | null {
  const match = ADDRESS_RE.exec(line);
  if (!match) return null;
  const email = match[2]?.toLowerCase() ?? null;
  if (!email) return null;
  const displayName = match[1]?.trim() || null;
  const [localPart, domain] = email.split("@");
  return { displayName, email, localPart: localPart ?? null, domain: domain ?? null };
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, " ");
}

export function analyzeForwarding(parsed: ParsedEmail): ForwardingAnalysis {
  const detectionEvidence: string[] = [];

  if (FORWARD_SUBJECT_RE.test(parsed.subject ?? "")) {
    detectionEvidence.push("subject_fwd_prefix");
  }

  const textBlob = parsed.body.text ?? "";
  const htmlBlob = parsed.body.html ? stripHtml(parsed.body.html) : "";
  const combined = `${textBlob}\n${htmlBlob}`;

  let nestedForwardCount = 0;
  let firstBlockIndex = -1;

  for (const marker of FORWARD_BLOCK_MARKERS) {
    const matches = Array.from(combined.matchAll(marker.pattern));
    if (matches.length === 0) continue;
    detectionEvidence.push(marker.name);
    nestedForwardCount += matches.length;
    const idx = matches[0].index ?? -1;
    if (idx !== -1 && (firstBlockIndex === -1 || idx < firstBlockIndex)) {
      firstBlockIndex = idx;
    }
  }

  const isForwarded = detectionEvidence.length > 0;

  if (!isForwarded) {
    return {
      emailId: parsed.emailId,
      isForwarded: false,
      forwarder: null,
      originalSender: null,
      originalSubject: null,
      nestedForwardCount: 0,
      detectionEvidence: [],
      confidence: "none",
    };
  }

  const forwarder = parsed.from[0] ?? null;

  // Only attempt to extract an original sender when a structured block
  // was found — a bare "Fwd:" subject with no recognizable block is
  // real signal that forwarding happened, but not enough structure to
  // reliably parse who the original sender was.
  let originalSender: EmailAddress | "UNKNOWN" = "UNKNOWN";
  let originalSubject: string | null = null;

  if (firstBlockIndex !== -1) {
    const window = combined.slice(firstBlockIndex, firstBlockIndex + BLOCK_SCAN_WINDOW);
    const fromMatch = FROM_LINE_RE.exec(window);
    if (fromMatch) {
      const parsedAddr = parseAddressLine(fromMatch[1]);
      if (parsedAddr) originalSender = parsedAddr;
    }
    const subjectMatch = SUBJECT_LINE_RE.exec(window);
    if (subjectMatch) originalSubject = subjectMatch[1].trim();
  }

  return {
    emailId: parsed.emailId,
    isForwarded: true,
    forwarder,
    originalSender,
    originalSubject,
    nestedForwardCount,
    detectionEvidence,
    confidence: firstBlockIndex !== -1 && originalSender !== "UNKNOWN" ? "high" : "low",
  };
}
