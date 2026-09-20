import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeForwarding } from "../src/analyzers/forwardingAnalyzer";
import type { ParsedEmail } from "../src/schemas/types";

// Regression tests for Prompt 5 (forwarded-email model).

function baseParsedEmail(overrides: Partial<ParsedEmail> = {}): ParsedEmail {
  return {
    emailId: "fwd-test",
    subject: "Hello",
    from: [{ displayName: "A Friend", email: "friend@gmail.com", localPart: "friend", domain: "gmail.com" }],
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    returnPath: [],
    date: null,
    messageId: "<abc@gmail.com>",
    headers: { normalized: {}, raw: [] },
    body: { text: "Hello there.", html: null },
    attachments: [],
    ...overrides,
  } as ParsedEmail;
}

// A. Forwarded legitimate promotional email — clean Gmail-style block
// with a fully parseable From: line.
test("A: forwarded legitimate promotional email — original sender correctly extracted, forwarder is NOT assumed to be the author", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: Our Anniversary Sale - Save Big!",
    body: {
      text: `---------- Forwarded message ---------
From: Brand Promotions <promo@brand-example.com>
Date: Mon, Jan 1, 2026 at 10:00 AM
Subject: Our Anniversary Sale - Save Big!
To: A Friend <friend@gmail.com>

Come celebrate our anniversary with huge savings!`,
      html: null,
    },
  });

  const result = analyzeForwarding(parsed);

  assert.equal(result.isForwarded, true);
  assert.equal(result.forwarder?.email, "friend@gmail.com", "forwarder must be the outer From, never assumed to be the author");
  assert.notEqual(result.originalSender, "UNKNOWN");
  assert.equal((result.originalSender as any)?.email, "promo@brand-example.com");
  assert.equal(result.originalSubject, "Our Anniversary Sale - Save Big!");
  assert.equal(result.confidence, "high");
});

// B. Normal, non-forwarded email.
test("B: a normal non-forwarded email is not flagged as forwarded", () => {
  const parsed = baseParsedEmail({ subject: "Meeting notes", body: { text: "See you at 3pm.", html: null } });
  const result = analyzeForwarding(parsed);

  assert.equal(result.isForwarded, false);
  assert.equal(result.forwarder, null);
  assert.equal(result.originalSender, null);
  assert.equal(result.confidence, "none");
});

// C. Forwarded phishing email — detection itself is content-neutral;
// forwarding must never be treated as malicious on its own (this
// function returns descriptive metadata only, no risk evidence).
test("C: forwarded phishing email is still detected as forwarded, with no risk-scoring side effects from this function", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: Urgent - verify your account",
    body: {
      text: `---------- Forwarded message ---------
From: IT Support <it-support@mailer.example>
Subject: Urgent - verify your account
To: friend@gmail.com

Please verify your account immediately.`,
      html: null,
    },
  });

  const result = analyzeForwarding(parsed);
  assert.equal(result.isForwarded, true);
  assert.equal((result.originalSender as any)?.email, "it-support@mailer.example");
  // No score/classification/severity fields exist on ForwardingAnalysis
  // at all — structurally incapable of contributing risk evidence.
  assert.equal((result as any).weight, undefined);
  assert.equal((result as any).severity, undefined);
});

// D. Forwarded email where the original sender cannot be reliably
// extracted — must label UNKNOWN, never invent a sender.
test("D: forwarded email with only a subject prefix (no parseable block) labels original sender UNKNOWN, not invented", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: check this out",
    body: { text: "Hey, thought you'd find this interesting — no forward header block present.", html: null },
  });

  const result = analyzeForwarding(parsed);
  assert.equal(result.isForwarded, true, "the Fwd: subject prefix alone is still real forwarding signal");
  assert.equal(result.originalSender, "UNKNOWN");
  assert.equal(result.confidence, "low");
});

test("D2: a forward block present but with a malformed/missing From: line also labels UNKNOWN", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: no from line",
    body: {
      text: `---------- Forwarded message ---------
Subject: no from line
To: friend@gmail.com

body text`,
      html: null,
    },
  });

  const result = analyzeForwarding(parsed);
  assert.equal(result.isForwarded, true);
  assert.equal(result.originalSender, "UNKNOWN");
});

// E. Nested forwarding — two forward blocks. originalSender should
// reflect only the OUTERMOST block; nestedForwardCount reflects both.
test("E: nested forwarding — two forward blocks are both detected, originalSender comes from the outermost one", () => {
  const parsed = baseParsedEmail({
    subject: "Fwd: Fwd: Sale",
    body: {
      text: `---------- Forwarded message ---------
From: Middle Forwarder <middle@example.com>
Subject: Fwd: Sale
To: friend@gmail.com

---------- Forwarded message ---------
From: Original Brand <promo@brand-example.com>
Subject: Sale
To: middle@example.com

Original content.`,
      html: null,
    },
  });

  const result = analyzeForwarding(parsed);
  assert.equal(result.isForwarded, true);
  assert.equal(result.nestedForwardCount, 2, "both forward blocks should be counted");
  assert.equal(
    (result.originalSender as any)?.email,
    "middle@example.com",
    "originalSender reflects the OUTERMOST block only — deeper nesting is intentionally not resolved"
  );
});
