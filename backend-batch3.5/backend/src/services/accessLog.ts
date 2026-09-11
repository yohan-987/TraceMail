import { promises as fs } from "fs";
import path from "path";

// Batch 6 — single flat JSON-array log at data/access-log.json, same
// read-modify-write convention as emailStore.ts (ENOENT -> treat as
// empty/absent, mkdir -recursive before writing, JSON.stringify with
// 2-space indent). Deliberately one shared file, not one per email —
// this is a small, append-mostly log, not per-email storage at the
// scale EmailRecord data justifies its own directory for.

const DEFAULT_LOG_PATH = path.join(__dirname, "..", "..", "data", "access-log.json");

function logPath(): string {
  // Mirrors emailStore.ts's EMAIL_DATA_DIR override so tests can
  // isolate this too, without touching production data.
  if (process.env.ACCESS_LOG_PATH && process.env.ACCESS_LOG_PATH.trim() !== "") {
    return path.resolve(process.env.ACCESS_LOG_PATH);
  }
  return DEFAULT_LOG_PATH;
}

export interface AccessLogEntry {
  emailId: string;
  viewedBy: string;
  viewedAt: string;
}

async function readAll(): Promise<AccessLogEntry[]> {
  try {
    const raw = await fs.readFile(logPath(), "utf-8");
    try {
      return JSON.parse(raw) as AccessLogEntry[];
    } catch {
      // A corrupted log file must never break the email-view request
      // that triggered logging it — access logging is inherently
      // best-effort telemetry, not evidence integrity (unlike
      // emailStore.ts's parsed.json, which throws a controlled 500 on
      // the same failure). Degrade to an empty log instead.
      console.error("[accessLog] log file unreadable, starting fresh");
      return [];
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

async function writeAll(entries: AccessLogEntry[]): Promise<void> {
  await fs.mkdir(path.dirname(logPath()), { recursive: true });
  await fs.writeFile(logPath(), JSON.stringify(entries, null, 2), "utf-8");
}

/**
 * Deviation from the task spec's literal signature, flagged explicitly:
 * the spec wrote `recordAccess(...): void` and
 * `getAccessLog(...): AccessLogEntry[]` — fully synchronous. But real
 * file I/O can't be synchronous without fs.readFileSync/writeFileSync,
 * and this codebase's storage layer (emailStore.ts) is fully async
 * throughout with zero sync fs calls anywhere. Introducing the one sync
 * disk write in an otherwise all-async Express app would block the
 * event loop on every single email view — a real cost for a codebase
 * this size, for the sake of matching a type signature literally
 * rather than the pattern that signature was presumably shorthand for.
 *
 * recordAccess() keeps its literal `void` signature (the caller never
 * awaits it and never sees a promise) by firing the actual write in an
 * un-awaited async IIFE — fire-and-forget, consistent with access
 * logging being best-effort: a failed log write must never delay or
 * fail the response the analyst is actually waiting on. Errors are
 * caught and logged here, never thrown to the caller.
 *
 * getAccessLog() could not stay synchronous this way (its caller needs
 * the real array back to respond to the request), so it's
 * `Promise<AccessLogEntry[]>` instead of a bare array — the one place
 * this file's signatures differ from the literal spec. Await it from
 * routes/emails.ts.
 */
export function recordAccess(emailId: string, viewedBy: string): void {
  void (async () => {
    try {
      const entries = await readAll();
      entries.push({ emailId, viewedBy, viewedAt: new Date().toISOString() });
      await writeAll(entries);
    } catch (err) {
      console.error(`[accessLog] failed to record access for ${emailId}:`, err);
    }
  })();
}

export async function getAccessLog(emailId: string): Promise<AccessLogEntry[]> {
  const entries = await readAll();
  return entries.filter((e) => e.emailId === emailId);
}
