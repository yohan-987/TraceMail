import type { ParsedEmail, HeaderAnalysis, IOCSet } from "../schemas/types";
import net from "net";

const URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
// Broader than findFirstIp — finds every IPv4 literal in a blob of text,
// not just the first. Used for scanning body content, not Received lines
// (headerForensics already extracts those per-hop).
const IPV4_ALL_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

function stripHtmlTags(html: string): string {
  return html.replace(/<[^>]*>/g, " ");
}

function extractUrls(text: string): string[] {
  return Array.from(text.matchAll(URL_RE)).map((m) => m[0]);
}

function extractEmails(text: string): string[] {
  return Array.from(text.matchAll(EMAIL_RE)).map((m) => m[0].toLowerCase());
}

function extractIpv4s(text: string): string[] {
  return Array.from(text.matchAll(IPV4_ALL_RE))
    .map((m) => m[1])
    .filter((ip) => net.isIP(ip) === 4);
}

export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function dedupe<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}

/**
 * Extracts and deduplicates indicators of compromise from the parsed
 * email body/headers, plus reuses the Received-chain IPs headerForensics
 * already parsed (avoids re-deriving the same evidence twice). Never
 * visits any extracted URL — extraction only, no network activity.
 */
export function extractIOCs(parsed: ParsedEmail, headerAnalysis: HeaderAnalysis): IOCSet {
  const textBlob = parsed.body.text ?? "";
  const htmlBlob = parsed.body.html ? stripHtmlTags(parsed.body.html) : "";
  const rawHtml = parsed.body.html ?? ""; // URLs can hide in href="" attrs that stripping tags removes
  const combinedText = `${textBlob}\n${htmlBlob}`;

  // URLs: from plain text, de-tagged HTML, raw HTML (for href attributes),
  // and any header value that happens to carry one (e.g. List-Unsubscribe).
  const headerText = parsed.headers.raw.map((h) => h.value).join("\n");
  const urls = dedupe([
    ...extractUrls(textBlob),
    ...extractUrls(htmlBlob),
    ...extractUrls(rawHtml),
    ...extractUrls(headerText),
  ]);

  // Domains: from URL hostnames, plus every known address field's domain.
  const addressDomains = [
    ...parsed.from,
    ...parsed.to,
    ...parsed.cc,
    ...parsed.bcc,
    ...parsed.replyTo,
    ...parsed.returnPath,
  ]
    .map((a) => a.domain)
    .filter((d): d is string => Boolean(d));

  const urlDomains = urls.map(hostnameOf).filter((d): d is string => Boolean(d));
  const domains = dedupe([...addressDomains, ...urlDomains].map((d) => d.toLowerCase()));

  // IPs: body-mentioned IPv4s plus every candidate source IP already
  // found in the Received chain (Batch 2) — reused, not re-parsed.
  const receivedIps = headerAnalysis.receivedChain
    .map((hop) => hop.fromIp)
    .filter((ip): ip is string => Boolean(ip));
  const bodyIps = extractIpv4s(combinedText);
  const ips = dedupe([...receivedIps, ...bodyIps]);

  // Emails: known address fields plus anything mentioned in the body content.
  const addressEmails = [
    ...parsed.from,
    ...parsed.to,
    ...parsed.cc,
    ...parsed.bcc,
    ...parsed.replyTo,
    ...parsed.returnPath,
  ]
    .map((a) => a.email)
    .filter((e): e is string => Boolean(e));
  const bodyEmails = extractEmails(combinedText);
  const emails = dedupe([...addressEmails, ...bodyEmails]);

  // Hashes: attachment SHA-256s already computed at parse time (Batch 1).
  const hashes = dedupe(parsed.attachments.map((a) => a.sha256));

  return {
    emailId: parsed.emailId,
    ips,
    domains,
    urls,
    hashes,
    emails,
  };
}
