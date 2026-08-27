import { test } from "node:test";
import assert from "node:assert/strict";
import { extractIOCs } from "../src/analyzers/iocExtractor";
import type { ParsedEmail, HeaderAnalysis } from "../src/schemas/types";

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "EMAIL-TEST-IOC",
    subject: "Test",
    from: [{ displayName: null, email: "sender@example.com", localPart: "sender", domain: "example.com" }],
    to: [{ displayName: null, email: "victim@target.org", localPart: "victim", domain: "target.org" }],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: "<abc@example.com>",
    headers: { normalized: {}, raw: [] },
    body: { text: null, html: null },
    attachments: [],
    ...overrides,
  };
}

function emptyHeaderAnalysis(): HeaderAnalysis {
  return { emailId: "EMAIL-TEST-IOC", anomalies: [], receivedChain: [], status: "VERIFIED" };
}

test("extracts and dedupes URLs from plain text body", () => {
  const parsed = baseParsedEmail({
    body: { text: "Visit http://evil.com/login and also http://evil.com/login again.", html: null },
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.deepEqual(iocs.urls, ["http://evil.com/login"]);
});

test("extracts URLs from HTML body, including inside href attributes", () => {
  const parsed = baseParsedEmail({
    body: { text: null, html: '<a href="https://phish.example/reset">Click here</a>' },
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.ok(iocs.urls.includes("https://phish.example/reset"));
});

test("extracts domains from address fields and from URL hostnames", () => {
  const parsed = baseParsedEmail({
    body: { text: "Go to http://malicious-domain.net/x", html: null },
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.ok(iocs.domains.includes("example.com"));
  assert.ok(iocs.domains.includes("target.org"));
  assert.ok(iocs.domains.includes("malicious-domain.net"));
});

test("extracts IPs mentioned in body content", () => {
  const parsed = baseParsedEmail({ body: { text: "Connect to 203.0.113.9 for details.", html: null } });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.ok(iocs.ips.includes("203.0.113.9"));
});

test("reuses Received-chain candidate IPs from headerAnalysis rather than re-deriving", () => {
  const parsed = baseParsedEmail();
  const headerAnalysis: HeaderAnalysis = {
    emailId: "EMAIL-TEST-IOC",
    anomalies: [],
    status: "VERIFIED",
    receivedChain: [
      {
        hop: 1,
        fromHostname: "mail.sender.com",
        fromIp: "198.51.100.5",
        fromIpClassification: "PUBLIC",
        byHostname: "mx.target.org",
        timestampRaw: null,
        timestampIso: null,
        rawHeader: "Received: from mail.sender.com [198.51.100.5] by mx.target.org",
      },
    ],
  };
  const iocs = extractIOCs(parsed, headerAnalysis);
  assert.ok(iocs.ips.includes("198.51.100.5"));
});

test("extracts emails mentioned in body content in addition to address fields", () => {
  const parsed = baseParsedEmail({
    body: { text: "Please cc accounts@othercompany.com on this.", html: null },
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.ok(iocs.emails.includes("accounts@othercompany.com"));
  assert.ok(iocs.emails.includes("sender@example.com"));
});

test("extracts attachment hashes as hash IOCs", () => {
  const parsed = baseParsedEmail({
    attachments: [{ filename: "invoice.pdf", mimeType: "application/pdf", sizeBytes: 100, sha256: "abc123" }],
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.ok(iocs.hashes.includes("abc123"));
});

test("never contains duplicate entries in any IOC list", () => {
  const parsed = baseParsedEmail({
    body: {
      text: "http://evil.com/a http://evil.com/a sender@example.com sender@example.com",
      html: null,
    },
  });
  const iocs = extractIOCs(parsed, emptyHeaderAnalysis());
  assert.equal(iocs.urls.length, new Set(iocs.urls).size);
  assert.equal(iocs.emails.length, new Set(iocs.emails).size);
  assert.equal(iocs.domains.length, new Set(iocs.domains).size);
  assert.equal(iocs.ips.length, new Set(iocs.ips).size);
});
