import { google, gmail_v1 } from "googleapis";
import { promises as fs } from "fs";
import path from "path";
import { ingestEmailBuffer } from "./emailIngestPipeline";

// Batch 1 — Gmail OAuth + polling ingestion.
//
// This is a second ingestion SOURCE, not a replacement for the .eml
// upload path (routes/emails.ts). Every message this module reads is
// fed through the exact same ingestEmailBuffer() pipeline the upload
// route calls, so a Gmail-sourced email produces an identical
// EmailRecord shape to an uploaded one — nothing downstream needs to
// know or care which source an email came from.
//
// Deliberately polling only (no Pub/Sub push): push requires standing
// up Cloud Pub/Sub infrastructure and a public webhook, which is real
// engineering cost and external-dependency risk this build doesn't
// take on. See the platform reference doc, §6.1 / §10.
//
// Credentials come from environment variables only — never hard-coded,
// never logged:
//   GMAIL_CLIENT_ID
//   GMAIL_CLIENT_SECRET
//   GMAIL_REFRESH_TOKEN
//   GMAIL_POLL_INTERVAL_SECONDS  (optional, default 45)
// The OAuth app stays in Google's "Testing" publishing status — nothing
// here assumes production verification.

const CURSOR_PATH = path.join(__dirname, "..", "..", "data", "gmail-cursor.json");

interface GmailCursor {
  historyId: string | null;
}

export interface GmailStatus {
  configured: boolean;
  lastPollAt: string | null;
  lastPollMessageCount: number | null;
}

// Module-level status the /gmail/status route reads. Intentionally not
// persisted — it's a live "what happened last poll" indicator, not
// evidence, so it resets on restart same as the rest of the process.
const status: GmailStatus = {
  configured: false,
  lastPollAt: null,
  lastPollMessageCount: null,
};

export function getGmailStatus(): GmailStatus {
  return { ...status };
}

function isConfigured(): boolean {
  return Boolean(
    process.env.GMAIL_CLIENT_ID &&
      process.env.GMAIL_CLIENT_SECRET &&
      process.env.GMAIL_REFRESH_TOKEN
  );
}

function getOAuthClient() {
  const client = new google.auth.OAuth2(
    process.env.GMAIL_CLIENT_ID,
    process.env.GMAIL_CLIENT_SECRET
  );
  // Refresh-token grant only — no interactive consent flow at runtime.
  // Never log this credential; googleapis itself does not log it either.
  client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
  return client;
}

async function readCursor(): Promise<GmailCursor> {
  try {
    const raw = await fs.readFile(CURSOR_PATH, "utf-8");
    const parsed = JSON.parse(raw) as Partial<GmailCursor>;
    return { historyId: parsed.historyId ?? null };
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      return { historyId: null };
    }
    // A corrupted cursor file must not crash polling — degrade to "no
    // cursor yet" and let the next successful write repair it, same
    // "one bad thing never breaks the pipeline" convention as the rest
    // of the codebase.
    console.error("[gmail] cursor file unreadable, starting fresh:", err);
    return { historyId: null };
  }
}

async function writeCursor(cursor: GmailCursor): Promise<void> {
  await fs.mkdir(path.dirname(CURSOR_PATH), { recursive: true });
  await fs.writeFile(CURSOR_PATH, JSON.stringify(cursor, null, 2), "utf-8");
}

/** Gmail's `raw` field is base64url — swap to the standard alphabet
 *  before decoding to bytes. */
function decodeRawMessage(raw: string): Buffer {
  const normalized = raw.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(normalized, "base64");
}

async function fetchAndIngestMessage(
  gmail: gmail_v1.Gmail,
  messageId: string
): Promise<boolean> {
  const msg = await gmail.users.messages.get({
    userId: "me",
    id: messageId,
    format: "raw",
  });
  if (!msg.data.raw) return false;

  const buffer = decodeRawMessage(msg.data.raw);
  if (buffer.length === 0) return false;

  await ingestEmailBuffer({
    buffer,
    filename: `gmail-${messageId}.eml`,
    caseId: null,
    source: "gmail",
    sourceMessageId: messageId,
  });
  return true;
}

/**
 * Lists messages added since the last processed historyId, ingests each
 * through the shared pipeline, and advances the cursor. Never throws —
 * every failure mode (auth, network, an expired/invalid historyId, one
 * bad message) is caught, logged, and left for the next interval to
 * retry, so a Gmail outage degrades this source without ever taking
 * down the server or the .eml upload path.
 *
 * Returns the number of messages successfully ingested this cycle.
 */
export async function pollInbox(): Promise<number> {
  if (!isConfigured()) {
    status.configured = false;
    console.log("[gmail] not configured, skipping");
    return 0;
  }
  status.configured = true;

  try {
    const auth = getOAuthClient();
    const gmail = google.gmail({ version: "v1", auth });
    const cursor = await readCursor();

    if (!cursor.historyId) {
      // First run ever (or cursor was reset below): establish a
      // starting point from the current profile rather than
      // back-filling the whole mailbox on first boot.
      const profile = await gmail.users.getProfile({ userId: "me" });
      await writeCursor({ historyId: profile.data.historyId ?? null });
      status.lastPollAt = new Date().toISOString();
      status.lastPollMessageCount = 0;
      console.log("[gmail] checked inbox, 0 new messages (cursor initialized)");
      return 0;
    }

    let historyResponse;
    try {
      historyResponse = await gmail.users.history.list({
        userId: "me",
        startHistoryId: cursor.historyId,
        historyTypes: ["messageAdded"],
      });
    } catch (err) {
      // A historyId can go stale (mailbox history is only retained for
      // ~a week) and Gmail returns 404 for it. Recovering means
      // re-establishing the cursor from the current profile — this
      // cycle's messages are skipped rather than replaying the whole
      // mailbox, but polling recovers on its own instead of staying
      // broken until someone notices.
      console.error("[gmail] history.list failed, resetting cursor:", err);
      const profile = await gmail.users.getProfile({ userId: "me" });
      await writeCursor({ historyId: profile.data.historyId ?? null });
      status.lastPollAt = new Date().toISOString();
      status.lastPollMessageCount = 0;
      return 0;
    }

    const messageIds = Array.from(
      new Set(
        (historyResponse.data.history ?? []).flatMap((h) =>
          (h.messagesAdded ?? [])
            .map((m) => m.message?.id)
            .filter((id): id is string => Boolean(id))
        )
      )
    );

    let ingested = 0;
    for (const messageId of messageIds) {
      try {
        const ok = await fetchAndIngestMessage(gmail, messageId);
        if (ok) ingested += 1;
      } catch (err) {
        // One bad message must not stop the rest of the batch, and
        // must not prevent the cursor from advancing past the ones
        // that did succeed.
        console.error(`[gmail] failed to ingest message ${messageId}:`, err);
      }
    }

    await writeCursor({ historyId: historyResponse.data.historyId ?? cursor.historyId });
    status.lastPollAt = new Date().toISOString();
    status.lastPollMessageCount = ingested;
    console.log(`[gmail] checked inbox, ${ingested} new messages`);
    return ingested;
  } catch (err) {
    // Any other failure (auth rejected, network down, rate limited,
    // etc.) — log server-side and let the next interval retry.
    console.error("[gmail] poll cycle failed:", err);
    status.lastPollAt = new Date().toISOString();
    status.lastPollMessageCount = null;
    return 0;
  }
}

let pollTimer: ReturnType<typeof setInterval> | null = null;

/**
 * Starts the Gmail polling loop if credentials are configured. Safe to
 * call unconditionally from server.ts on every boot — when Gmail isn't
 * configured this is a one-line log and a no-op, so .eml upload keeps
 * working standalone exactly as before this batch.
 */
export function startGmailPolling(): void {
  if (!isConfigured()) {
    status.configured = false;
    console.log("[gmail] not configured, skipping");
    return;
  }
  if (pollTimer) return; // already running

  const intervalSeconds = Number(process.env.GMAIL_POLL_INTERVAL_SECONDS ?? 45);
  const intervalMs = Math.max(Number.isFinite(intervalSeconds) ? intervalSeconds : 45, 1) * 1000;

  // Fire once immediately so a configured inbox doesn't wait a full
  // interval for its first poll, then continue on the interval.
  void pollInbox();
  pollTimer = setInterval(() => {
    void pollInbox();
  }, intervalMs);
}

/** Exposed for tests / graceful shutdown — not currently called from
 *  server.ts, since the process exiting clears the interval anyway. */
export function stopGmailPolling(): void {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}
