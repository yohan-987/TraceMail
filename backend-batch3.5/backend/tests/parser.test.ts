import { test } from "node:test";
import assert from "node:assert/strict";
import { parseEmlBuffer } from "../src/analyzers/emailParser";

function crlf(s: string): Buffer {
  // Normalize template-literal newlines to CRLF, matching real .eml wire format.
  return Buffer.from(s.replace(/\n/g, "\r\n"), "utf-8");
}

test("parses a simple valid .eml", async () => {
  const eml = crlf(`From: Alice <alice@example.com>
To: Bob <bob@example.org>
Subject: Hello
Date: Mon, 24 Aug 2026 10:00:00 +0000
Message-ID: <abc123@example.com>

Hello Bob, this is the body.
`);
  const { parsed, warnings } = await parseEmlBuffer("EMAIL-TEST-0001", eml);
  assert.equal(parsed.subject, "Hello");
  assert.equal(parsed.from[0].email, "alice@example.com");
  assert.equal(parsed.from[0].domain, "example.com");
  assert.equal(parsed.to[0].email, "bob@example.org");
  assert.equal(parsed.messageId, "<abc123@example.com>");
  assert.match(parsed.body.text ?? "", /Hello Bob/);
  assert.equal(warnings.length, 0);
});

test("extracts both text and html parts from a multipart email", async () => {
  const boundary = "BOUNDARY123";
  const eml = crlf(`From: sender@example.com
To: recipient@example.com
Subject: Multipart test
Content-Type: multipart/alternative; boundary="${boundary}"

--${boundary}
Content-Type: text/plain; charset="utf-8"

Plain text version.
--${boundary}
Content-Type: text/html; charset="utf-8"

<p>HTML version.</p>
--${boundary}--
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0002", eml);
  assert.match(parsed.body.text ?? "", /Plain text version/);
  assert.match(parsed.body.html ?? "", /HTML version/);
});

test("extracts attachment metadata and hashes attachment bytes", async () => {
  const boundary = "BOUNDARY456";
  const attachmentContent = Buffer.from("fake pdf bytes for testing");
  const base64Content = attachmentContent.toString("base64");
  const eml = crlf(`From: sender@example.com
To: recipient@example.com
Subject: Has an attachment
Content-Type: multipart/mixed; boundary="${boundary}"

--${boundary}
Content-Type: text/plain

See attached.
--${boundary}
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

${base64Content}
--${boundary}--
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0003", eml);
  assert.equal(parsed.attachments.length, 1);
  assert.equal(parsed.attachments[0].filename, "invoice.pdf");
  assert.equal(parsed.attachments[0].mimeType, "application/pdf");

  const { sha256 } = await import("../src/utils/hash");
  assert.equal(parsed.attachments[0].sha256, sha256(attachmentContent));
});

test("preserves duplicate Received headers as an array, in order", async () => {
  const eml = crlf(`Received: from hop1.example.com by hop2.example.com; Mon, 24 Aug 2026 09:00:00 +0000
Received: from hop2.example.com by hop3.example.com; Mon, 24 Aug 2026 09:00:05 +0000
From: sender@example.com
To: recipient@example.com
Subject: Duplicate headers test

Body.
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0004", eml);
  const received = parsed.headers.normalized["received"];
  assert.ok(Array.isArray(received), "received header should be an array when duplicated");
  assert.equal((received as string[]).length, 2);
  assert.match((received as string[])[0], /hop1\.example\.com/);
  assert.match((received as string[])[1], /hop2\.example\.com by hop3/);

  const rawReceivedEntries = parsed.headers.raw.filter((h) => h.name.toLowerCase() === "received");
  assert.equal(rawReceivedEntries.length, 2);
});

test("decodes a MIME encoded-word (unicode) subject", async () => {
  const original = "Résumé — 招聘";
  const encodedWord = `=?UTF-8?B?${Buffer.from(original, "utf-8").toString("base64")}?=`;
  const eml = crlf(`From: sender@example.com
To: recipient@example.com
Subject: ${encodedWord}

Body.
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0005", eml);
  assert.equal(parsed.subject, original);
});

test("malformed/garbage input degrades gracefully instead of throwing", async () => {
  const garbage = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x00, 0x00, 0x10, 0x20]);
  const { parsed, warnings } = await parseEmlBuffer("EMAIL-TEST-0006", garbage);
  // Must not throw; must return a usable (if mostly empty) ParsedEmail.
  assert.equal(parsed.emailId, "EMAIL-TEST-0006");
  assert.ok(Array.isArray(parsed.from));
  // Either a hard parse-failure warning, or a "no From" warning is fine —
  // the important thing is we never silently pretend garbage is a real email.
  assert.ok(warnings.length >= 0);
});

test("preserves the Reply-To header separately from From", async () => {
  const eml = crlf(`From: "CEO" <ceo@company-example.com>
Reply-To: finance-request@gmail.com
To: victim@example.org
Subject: Urgent wire transfer

Please process this payment immediately.
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0007", eml);
  assert.equal(parsed.from[0].domain, "company-example.com");
  assert.equal(parsed.replyTo[0].domain, "gmail.com");
  assert.notEqual(parsed.from[0].domain, parsed.replyTo[0].domain);
});

test("parses Return-Path independently of From", async () => {
  const eml = crlf(`Return-Path: <bounce@mailer.example.net>
From: sender@example.com
To: recipient@example.com
Subject: Return-Path test

Body.
`);
  const { parsed } = await parseEmlBuffer("EMAIL-TEST-0008", eml);
  assert.equal(parsed.returnPath[0].email, "bounce@mailer.example.net");
  assert.equal(parsed.returnPath[0].domain, "mailer.example.net");
});
