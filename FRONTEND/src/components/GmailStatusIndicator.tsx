import { useEffect, useState } from 'react';
import { StatusDot } from '@/components/ui/Primitives';
import { getGmailStatus, type ApiGmailStatus } from '@/api/api';

const POLL_INTERVAL_MS = 60_000;

// Header-level "is the Gmail live-ingestion source up" indicator.
// Deliberately separate from the .eml upload path — this only reflects
// whether the Gmail polling source (Batch 1) is configured and healthy,
// never whether the app can accept emails at all (upload always works).
export function GmailStatusIndicator() {
  const [status, setStatus] = useState<ApiGmailStatus | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const result = await getGmailStatus();
        if (!cancelled) setStatus(result);
      } catch {
        // A failed status check is not itself evidence Gmail stopped
        // working — leave whatever was last known showing rather than
        // flashing to "not configured" on a transient network blip.
      }
    }

    check();
    const interval = setInterval(check, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (!status || !status.configured) {
    return (
      <span
        className="flex items-center gap-1.5"
        title="Set GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN on the backend to enable live Gmail ingestion"
      >
        <StatusDot status="idle" />
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-600">
          Live Gmail: not configured
        </span>
      </span>
    );
  }

  // Configured but hasn't completed a poll cycle yet — a distinct state
  // from "connected," not the same visual, since nothing has actually
  // been confirmed working yet.
  const isConnected = status.lastPollAt !== null;

  const tooltip = isConnected
    ? `Last checked ${new Date(status.lastPollAt as string).toLocaleTimeString()}` +
      (status.lastPollMessageCount !== null
        ? ` · ${status.lastPollMessageCount} new message${status.lastPollMessageCount === 1 ? '' : 's'} last cycle`
        : ' · last poll cycle failed, retrying')
    : 'Waiting for first poll cycle';

  return (
    <span className="flex items-center gap-1.5" title={tooltip}>
      <StatusDot status={isConnected ? 'online' : 'warning'} />
      <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-400">
        {isConnected ? 'Live Gmail: connected' : 'Live Gmail: connecting'}
      </span>
    </span>
  );
}
