import {
  createContext,
  useContext,
  useState,
  useMemo,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { type ScannedEmail } from '@/data/mockData';
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

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [lastViewedEmailId, setLastViewedEmailId] = useState<string | null>(
    null
  );

  const [availableEmails, setAvailableEmails] = useState<ScannedEmail[]>([]);

  useEffect(() => {
    let cancelled = false;

    getEmails({ limit: 200, sort: 'date' })
      .then((response) => {
        if (cancelled) return;

        const mappedData = response.items.map(mapApiEmailToUiEmail);
        setAvailableEmails(mappedData);
      })
      .catch((err) => {
        console.error('Failed to load email list:', err);
      });

    return () => {
      cancelled = true;
    };
  }, []);

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

  const refreshEmails = useCallback(async () => {
    try {
      const response = await getEmails({ limit: 200, sort: 'date' });
      const mappedData = response.items.map(mapApiEmailToUiEmail);
      setAvailableEmails(mappedData);
    } catch (err) {
      console.error('Failed to refresh email list:', err);
    }
  }, []);

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