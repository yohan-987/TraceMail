import { useEffect, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Inbox } from 'lucide-react';
import { CaseSelector } from '@/components/CaseSelector';
import { InvestigationNavigation, type InvestigationSection } from '@/components/InvestigationNavigation';
import type { ScannedEmail } from '@/types/email';
import { cn } from '@/lib/utils';

interface InvestigationShellProps {
  breadcrumb: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  /** Hide the compact case-switcher dropdown — used when the page body already
   *  renders the full email table (InvestigationWorkspace) as the selector. */
  hideCaseSelector?: boolean;
  /** This page's own locally-selected email (not global) — powers the switcher. */
  selectedEmail?: ScannedEmail | null;
  availableEmails?: ScannedEmail[];
  onSelectEmail?: (id: string) => void;
  onClearEmail?: () => void;
  /**
   * Pass this ONLY once a specific email has entered the full investigation
   * workspace for this page (never while merely browsing the table) — it
   * renders the shared persistent bottom navigation for that email.
   */
  investigationNav?: { emailId: string; activeSection: InvestigationSection };
}

export function InvestigationShell({
  breadcrumb,
  title,
  subtitle,
  actions,
  children,
  hideCaseSelector,
  selectedEmail,
  availableEmails,
  onSelectEmail,
  onClearEmail,
  investigationNav,
}: InvestigationShellProps) {
  // The precise signal for "the investigation section changed" is
  // activeSection + emailId — not the route pathname. Every one of the
  // six investigation pages (Overview/Forensics/Indicators/
  // Infrastructure/AI Investigation/Report) already renders this one
  // shared shell, so resetting scroll here — keyed on that real
  // identity — covers all of them without any page needing its own
  // scroll-reset logic. (Layout's pathname-based reset still runs too,
  // for navigation outside the investigation shell; the two don't
  // conflict — both just set scrollTop to 0.)
  useEffect(() => {
    if (!investigationNav) return;
    document.getElementById('app-main-scroll')?.scrollTo({ top: 0 });
  }, [investigationNav?.activeSection, investigationNav?.emailId]);

  return (
    <div className="flex flex-col min-h-full">
      <div className={cn('px-8 py-6 max-w-[1600px] mx-auto w-full', investigationNav && 'pb-28')}>
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 mb-4 print:hidden">
          <Link to="/investigation" className="flex items-center gap-1 text-[11px] font-medium text-ink-500 hover:text-accent-400 transition-colors uppercase tracking-wider">
            <ArrowLeft className="w-3 h-3" /> Investigation
          </Link>
          <span className="text-ink-700 text-xs">/</span>
          <span className="text-[11px] font-medium text-ink-400 uppercase tracking-wider">{breadcrumb}</span>
        </div>

        {/* Case selector — hidden when the full email table is already shown below */}
        {!hideCaseSelector && onSelectEmail && onClearEmail && (
          <CaseSelector
            className="mb-5 print:hidden"
            selected={selectedEmail ?? null}
            availableEmails={availableEmails ?? []}
            onSelect={onSelectEmail}
            onClear={onClearEmail}
          />
        )}

        {/* Page heading */}
        <div className="flex items-end justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-ink-50">{title}</h1>
            {subtitle && <p className="text-xs text-ink-500 mt-1">{subtitle}</p>}
          </div>
          <div className="print:hidden">{actions}</div>
        </div>

        {children}
      </div>

      {/* Persistent investigation navigation — only rendered once a specific
          email is open in the full workspace, per the visibility rule. */}
      {investigationNav && (
        <InvestigationNavigation emailId={investigationNav.emailId} activeSection={investigationNav.activeSection} />
      )}
    </div>
  );
}

export function EmptyCaseState() {
  return (
    <div className="flex flex-col items-center justify-center py-20 rounded-xl border border-dashed border-base-500/30 bg-base-800/30">
      <div className="flex items-center justify-center w-14 h-14 rounded-xl bg-base-800 border border-base-500/30 mb-5">
        <Inbox className="w-6 h-6 text-ink-600" />
      </div>
      <h2 className="text-lg font-semibold text-ink-200">No Case Selected</h2>
      <p className="text-sm text-ink-500 mt-2 mb-5 text-center max-w-md">
        Select an email from the case selector above to begin investigation.
      </p>
      <Link
        to="/"
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-bold text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors uppercase tracking-wider"
      >
        <ArrowLeft className="w-3 h-3" /> Go to Triage Dashboard
      </Link>
    </div>
  );
}