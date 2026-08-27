import { Search, Bell, User, ChevronRight } from 'lucide-react';
import { useActiveCase } from '@/context/ActiveCaseContext';

export function Header() {
  // There is no global "active case" in this app — each investigation page
  // owns its own selection. The Header only ever shows the shared, read-only
  // "last viewed" convenience pointer, purely for orientation.
  const { lastViewedEmail } = useActiveCase();
  const hasLastViewed = lastViewedEmail !== null && lastViewedEmail !== undefined;

  return (
    <header className="sticky top-0 z-20 h-14 flex items-center justify-between px-6 bg-base-950/80 backdrop-blur-md border-b border-base-500/30 print:hidden">
      <div className="flex items-center gap-2 min-w-0">
        {hasLastViewed ? (
          <>
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-600 shrink-0">
              Last Viewed
            </span>
            <ChevronRight className="w-3 h-3 text-ink-700 shrink-0" />
            <span className="mono text-xs font-medium text-ink-300 shrink-0">{lastViewedEmail?.caseId || lastViewedEmail?.id}</span>
            <span className="text-ink-700 shrink-0">·</span>
            <span className="text-xs text-ink-400 truncate">{lastViewedEmail?.subject}</span>
          </>
        ) : (
          <>
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-600 shrink-0">
              No Case Viewed Yet
            </span>
            <span className="text-xs text-ink-600 ml-2">Open any investigation tab to begin</span>
          </>
        )}
      </div>

      <div className="flex items-center gap-1 shrink-0">
        <button className="flex items-center justify-center w-8 h-8 rounded-lg text-ink-500 hover:text-ink-200 hover:bg-base-800/60 transition-colors">
          <Search className="w-4 h-4" />
        </button>
        <button className="relative flex items-center justify-center w-8 h-8 rounded-lg text-ink-500 hover:text-ink-200 hover:bg-base-800/60 transition-colors">
          <Bell className="w-4 h-4" />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-accent-600 accent-glow-sm" />
        </button>
        <div className="w-px h-5 bg-base-500/30 mx-2" />
        <button className="flex items-center gap-2 pl-1 pr-3 py-1 rounded-lg hover:bg-base-800/60 transition-colors">
          <div className="flex items-center justify-center w-7 h-7 rounded-md bg-base-700 border border-base-500/40">
            <User className="w-3.5 h-3.5 text-ink-400" />
          </div>
          <div className="flex flex-col items-start">
            <span className="text-[11px] font-medium text-ink-200 leading-none">M. Chen</span>
            <span className="text-[9px] text-ink-600 leading-none mt-0.5">Analyst L3</span>
          </div>
        </button>
      </div>
    </header>
  );
}
