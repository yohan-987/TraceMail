import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from 'react';
import { type ScannedEmail } from '@/types/email';
import { getEmails } from '@/api/api';
import { mapApiEmailToUiEmail } from '@/api/emailMapper';

/**
 * This context intentionally does NOT hold a single global "selected email."
 * Each investigation page (Forensics, Indicators, Infrastructure, AI
 * Investigation, Reports, Investigation hub) owns its own local selection
 * state so tabs never force each other to display the same email.
 *
 * The one thing that IS shared is `lastViewedEmailId` — a convenience
 * pointer, updated whenever any page promotes an email into its full
 * detail view, and surfaced as the pinned "★ Last Viewed" row in every
 * email table and in the Header.
 *
 * `availableEmails` is the shared lightweight email dataset fetched from the
 * backend. It is NOT selection state.
 */
interface ActiveCaseContextValue {
  lastViewedEmailId: string | null;
  lastViewedEmail: ScannedEmail | null;
  setLastViewed: (id: string) => void;
  availableEmails: ScannedEmail[];
  getEmail: (id: string | null) => ScannedEmail | null;
  refreshEmails: () => Promise<void>;
}

const ActiveCaseContext = createContext<ActiveCaseContextValue | null>(null);

// Real-time-without-refresh: matches the reduced Gmail backend poll
// cadence (GMAIL_POLL_INTERVAL_SECONDS). This is a plain interval poll,
// not a push mechanism (WebSockets/SSE) — consistent with this
// project's own established tradeoff elsewhere (Gmail polling itself,
// GmailStatusIndicator.tsx) of "near-real-time at a fraction of the
// setup cost" rather than new realtime infrastructure. A GET /emails
// call against a flat-file store with a handful of records is cheap
// enough that 10s is safe to leave running indefinitely, not just for
// a short test session.
const POLL_INTERVAL_MS = 4_000;

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [lastViewedEmailId, setLastViewedEmailId] = useState<string | null>(
    null
  );

  const [availableEmails, setAvailableEmails] = useState<ScannedEmail[]>([]);

  // In-flight guard — same principle as gmailClient.ts's backend poll
  // loop: if a refresh is still awaiting the network when the next
  // interval tick fires (a slow connection, a large list), skip that
  // tick rather than firing an overlapping request. Never resets
  // availableEmails to anything if a request fails; only a successful
  // response ever calls setAvailableEmails.
  const isRefreshingRef = useRef(false);

  const refreshEmails = useCallback(async () => {
    if (isRefreshingRef.current) return;
    isRefreshingRef.current = true;
    try {
      const response = await getEmails({ limit: 200, sort: 'date' });
      const mappedData = response.items.map(mapApiEmailToUiEmail);
      setAvailableEmails(mappedData);
    } catch (err) {
      console.error('Failed to refresh email list:', err);
    } finally {
      isRefreshingRef.current = false;
    }
  }, []);

  useEffect(() => {
    // Immediate fetch on mount, then repeat on POLL_INTERVAL_MS — this
    // is what makes a newly-arrived Gmail-sourced email (or a fresh
    // .eml upload from elsewhere) show up without the user refreshing
    // the page. refreshEmails's own in-flight guard means a slow tick
    // is skipped rather than stacking concurrent requests.
    refreshEmails();

    const interval = setInterval(refreshEmails, POLL_INTERVAL_MS);

    return () => {
      clearInterval(interval);
    };
  }, [refreshEmails]);

  const getEmail = useCallback(
    (id: string | null): ScannedEmail | null => {
      if (!id) return null;

      return (
        availableEmails.find((email) => email.id === id) ?? null
      );
    },
    [availableEmails]
  );

  const setLastViewed = useCallback((id: string) => {
    setLastViewedEmailId(id);
  }, []);

  const lastViewedEmail = useMemo(
    () => getEmail(lastViewedEmailId),
    [lastViewedEmailId, getEmail]
  );

  const value = useMemo<ActiveCaseContextValue>(
    () => ({
      lastViewedEmailId,
      lastViewedEmail,
      setLastViewed,
      availableEmails,
      getEmail,
      refreshEmails,
    }),
    [
      lastViewedEmailId,
      lastViewedEmail,
      setLastViewed,
      availableEmails,
      getEmail,
      refreshEmails,
    ]
  );

  return (
    <ActiveCaseContext.Provider value={value}>
      {children}
    </ActiveCaseContext.Provider>
  );
}

export function useActiveCase(): ActiveCaseContextValue {
  const ctx = useContext(ActiveCaseContext);

  if (!ctx) {
    throw new Error('useActiveCase must be used within ActiveCaseProvider');
  }

  return ctx;
}