import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeHeaders } from "../src/analyzers/headerForensics";
import { classifyIp, findFirstIp } from "../src/utils/ip";
import type { ParsedEmail } from "../src/schemas/types";

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "EMAIL-TEST-HDR",
    subject: "Test",
    from: [{ displayName: "Sender", email: "sender@example.com", localPart: "sender", domain: "example.com" }],
    to: [],
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

// --- IP classification -----------------------------------------------

test("classifyIp: public IPv4", () => {
  assert.equal(classifyIp("8.8.8.8"), "PUBLIC");
});
test("classifyIp: private IPv4 ranges", () => {
  assert.equal(classifyIp("10.0.0.5"), "PRIVATE");
  assert.equal(classifyIp("172.16.0.1"), "PRIVATE");
  assert.equal(classifyIp("192.168.1.1"), "PRIVATE");
});
test("classifyIp: loopback and link-local", () => {
  assert.equal(classifyIp("127.0.0.1"), "LOOPBACK");
  assert.equal(classifyIp("169.254.1.1"), "LINK_LOCAL");
});
test("classifyIp: invalid input", () => {
  assert.equal(classifyIp("not-an-ip"), "INVALID");
  assert.equal(classifyIp("999.999.999.999"), "INVALID");
});
test("classifyIp: IPv6 loopback and public", () => {
  assert.equal(classifyIp("::1"), "LOOPBACK");
  assert.equal(classifyIp("2001:4860:4860::8888"), "PUBLIC");
});
test("findFirstIp: extracts bracketed IP from a Received-style line", () => {
  const line = "from mail.example.com (mail.example.com [203.0.113.5]) by mx.recipient.com";
  assert.equal(findFirstIp(line), "203.0.113.5");
});

// --- Address mismatches -------------------------------------------------

test("flags reply_to_mismatch when Reply-To domain differs from From", () => {
  const parsed = baseParsedEmail({
    replyTo: [{ displayName: null, email: "x@gmail.com", localPart: "x", domain: "gmail.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  const anomaly = headerAnalysis.anomalies.find((a) => a.type === "reply_to_mismatch");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "medium");
  assert.equal(anomaly?.weight, 40);
});

test("does not flag reply_to_mismatch when domains match", () => {
  const parsed = baseParsedEmail({
    replyTo: [{ displayName: null, email: "x@example.com", localPart: "x", domain: "example.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.anomalies.find((a) => a.type === "reply_to_mismatch"), undefined);
});

test("flags return_path_mismatch as low severity, distinct from reply-to", () => {
  const parsed = baseParsedEmail({
    returnPath: [{ displayName: null, email: "bounce@mailer.net", localPart: "bounce", domain: "mailer.net" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  const anomaly = headerAnalysis.anomalies.find((a) => a.type === "return_path_mismatch");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "low");
});

// --- Display name impersonation -----------------------------------------

test("flags brand impersonation: display name says PayPal, domain isn't PayPal's", () => {
  const parsed = baseParsedEmail({
    from: [{ displayName: "PayPal Security", email: "alert@paypa1-secure.com", localPart: "alert", domain: "paypa1-secure.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  const anomaly = headerAnalysis.anomalies.find((a) => a.type === "display_name_brand_impersonation");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "high");
});

test("does not flag brand impersonation when domain genuinely belongs to the brand", () => {
  const parsed = baseParsedEmail({
    from: [{ displayName: "Google Support", email: "support@google.com", localPart: "support", domain: "google.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.anomalies.find((a) => a.type === "display_name_brand_impersonation"), undefined);
});

test("flags authority-keyword impersonation: 'CEO' display name sent from free webmail", () => {
  const parsed = baseParsedEmail({
    from: [{ displayName: "CEO John Smith", email: "ceo.request@gmail.com", localPart: "ceo.request", domain: "gmail.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  const anomaly = headerAnalysis.anomalies.find((a) => a.type === "display_name_authority_impersonation");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "medium");
});

test("does not flag authority-keyword when sent from a normal corporate domain", () => {
  const parsed = baseParsedEmail({
    from: [{ displayName: "CEO John Smith", email: "john@company.com", localPart: "john", domain: "company.com" }],
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.anomalies.find((a) => a.type === "display_name_authority_impersonation"), undefined);
});

// --- Received chain -------------------------------------------------------

test("parses Received chain hops with hostname, IP, classification, and timestamp", () => {
  const raw = [
    {
      name: "Received",
      value:
        "Received: from mail.sender.com (mail.sender.com [203.0.113.5]) by mx.recipient.com with ESMTP; Mon, 24 Aug 2026 09:00:00 +0000",
    },
    {
      name: "Received",
      value: "Received: from internal.local (internal.local [10.0.0.5]) by mail.sender.com; Mon, 24 Aug 2026 08:59:55 +0000",
    },
  ];
  const parsed = baseParsedEmail({ headers: { normalized: {}, raw } });
  const { headerAnalysis } = analyzeHeaders(parsed);

  assert.equal(headerAnalysis.receivedChain.length, 2);
  const [hop1, hop2] = headerAnalysis.receivedChain;
  assert.equal(hop1.hop, 1);
  assert.equal(hop1.fromIp, "203.0.113.5");
  assert.equal(hop1.fromIpClassification, "PUBLIC");
  assert.equal(hop1.timestampIso !== null, true);

  assert.equal(hop2.hop, 2);
  assert.equal(hop2.fromIp, "10.0.0.5");
  assert.equal(hop2.fromIpClassification, "PRIVATE");
});

// --- Message-ID -------------------------------------------------------

test("flags message_id_domain_mismatch when Message-ID domain differs from From", () => {
  const parsed = baseParsedEmail({ messageId: "<xyz@totally-different.net>" });
  const { headerAnalysis } = analyzeHeaders(parsed);
  const anomaly = headerAnalysis.anomalies.find((a) => a.type === "message_id_domain_mismatch");
  assert.ok(anomaly);
  assert.equal(anomaly?.severity, "low");
});

test("flags message_id_missing when absent", () => {
  const parsed = baseParsedEmail({ messageId: null });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.ok(headerAnalysis.anomalies.find((a) => a.type === "message_id_missing"));
});

// --- SPF / DKIM / DMARC ---------------------------------------------------

test("parses SPF/DKIM/DMARC pass from Authentication-Results and flags nothing", () => {
  const parsed = baseParsedEmail({
    headers: {
      normalized: {
        "authentication-results":
          "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.i=@example.com; dmarc=pass (p=REJECT) header.from=example.com",
      },
      raw: [],
    },
  });
  const { headerAnalysis, authentication } = analyzeHeaders(parsed);
  assert.equal(authentication.spf.result, "pass");
  assert.equal(authentication.dkim.result, "pass");
  assert.equal(authentication.dmarc.result, "pass");
  assert.equal(authentication.dmarc.policy, "reject");
  assert.equal(headerAnalysis.anomalies.some((a) => a.type.startsWith("spf") || a.type.startsWith("dkim") || a.type.startsWith("dmarc")), false);
});

test("parses SPF/DKIM/DMARC fail and generates high-severity anomalies with correct weights", () => {
  const parsed = baseParsedEmail({
    headers: {
      normalized: {
        "authentication-results":
          "mx.google.com; spf=fail smtp.mailfrom=evil.com; dkim=fail header.i=@evil.com; dmarc=fail (p=REJECT) header.from=evil.com",
      },
      raw: [],
    },
  });
  const { headerAnalysis, authentication } = analyzeHeaders(parsed);
  assert.equal(authentication.spf.result, "fail");
  assert.equal(authentication.dkim.result, "fail");
  assert.equal(authentication.dmarc.result, "fail");

  const spfAnomaly = headerAnalysis.anomalies.find((a) => a.type === "spf_fail");
  const dkimAnomaly = headerAnalysis.anomalies.find((a) => a.type === "dkim_fail");
  const dmarcAnomaly = headerAnalysis.anomalies.find((a) => a.type === "dmarc_fail");
  assert.equal(spfAnomaly?.weight, 25);
  assert.equal(dkimAnomaly?.weight, 25);
  assert.equal(dmarcAnomaly?.weight, 30);
  assert.equal(spfAnomaly?.severity, "high");
});

test("falls back to Received-SPF when Authentication-Results is absent", () => {
  const parsed = baseParsedEmail({
    headers: {
      normalized: { "received-spf": "fail (google.com: domain of evil.com does not designate ... as permitted sender)" },
      raw: [],
    },
  });
  const { authentication, headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(authentication.spf.result, "fail");
  assert.ok(headerAnalysis.anomalies.find((a) => a.type === "spf_fail"));
});

test("does not flag any auth anomaly when result is 'none' or absent (INCONCLUSIVE != MALICIOUS)", () => {
  const parsed = baseParsedEmail({ headers: { normalized: {}, raw: [] } });
  const { authentication, headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(authentication.spf.result, "unknown");
  assert.equal(
    headerAnalysis.anomalies.some((a) => ["spf_fail", "dkim_fail", "dmarc_fail"].includes(a.type)),
    false
  );
});

// --- Status -------------------------------------------------------------

test("status is VERIFIED when there are no anomalies at all", () => {
  const parsed = baseParsedEmail({
    headers: {
      normalized: {
        "authentication-results": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
      },
      raw: [{ name: "From", value: "From: sender@example.com" }],
    },
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.status, "VERIFIED");
});

test("status is SUSPICIOUS when at least one anomaly is present", () => {
  const parsed = baseParsedEmail({
    replyTo: [{ displayName: null, email: "x@gmail.com", localPart: "x", domain: "gmail.com" }],
    headers: { normalized: {}, raw: [{ name: "From", value: "From: sender@example.com" }] },
  });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.status, "SUSPICIOUS");
});

test("status is UNAVAILABLE when there are no headers at all", () => {
  const parsed = baseParsedEmail({ headers: { normalized: {}, raw: [] } });
  const { headerAnalysis } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.status, "UNAVAILABLE");
});

// --- Every result belongs to the emailId, not global state ---------------

test("every output object carries the same emailId as the input", () => {
  const parsed = baseParsedEmail({ emailId: "EMAIL-SPECIFIC-ID" });
  const { headerAnalysis, authentication } = analyzeHeaders(parsed);
  assert.equal(headerAnalysis.emailId, "EMAIL-SPECIFIC-ID");
  assert.equal(authentication.emailId, "EMAIL-SPECIFIC-ID");
});
