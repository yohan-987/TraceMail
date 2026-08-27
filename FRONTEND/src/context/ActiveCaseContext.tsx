import { createContext, useContext, useState, useMemo, useCallback, type ReactNode } from 'react';
import { mockEmails, getEmailById, type ScannedEmail } from '@/data/mockData';

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
 */
interface ActiveCaseContextValue {
  lastViewedEmailId: string | null;
  lastViewedEmail: ScannedEmail | null;
  setLastViewed: (id: string) => void;
  availableEmails: ScannedEmail[];
  getEmail: (id: string | null) => ScannedEmail | null;
}

const ActiveCaseContext = createContext<ActiveCaseContextValue | null>(null);

export function ActiveCaseProvider({ children }: { children: ReactNode }) {
  const [lastViewedEmailId, setLastViewedEmailId] = useState<string | null>(null);

  const getEmail = useCallback((id: string | null): ScannedEmail | null => {
    if (!id) return null;
    return getEmailById(id) ?? null;
  }, []);

  const setLastViewed = useCallback((id: string) => {
    setLastViewedEmailId(id);
  }, []);

  const lastViewedEmail = useMemo(() => getEmail(lastViewedEmailId), [lastViewedEmailId, getEmail]);

  const value = useMemo<ActiveCaseContextValue>(
    () => ({
      lastViewedEmailId,
      lastViewedEmail,
      setLastViewed,
      availableEmails: mockEmails,
      getEmail,
    }),
    [lastViewedEmailId, lastViewedEmail, setLastViewed, getEmail]
  );

  return <ActiveCaseContext.Provider value={value}>{children}</ActiveCaseContext.Provider>;
}

export function useActiveCase(): ActiveCaseContextValue {
  const ctx = useContext(ActiveCaseContext);
  if (!ctx) throw new Error('useActiveCase must be used within ActiveCaseProvider');
  return ctx;
}
