import { Link } from 'react-router-dom';
import { Crosshair, FileSearch, Flag, Network, Brain, TrendingUp } from 'lucide-react';
import { cn } from '@/lib/utils';

export type InvestigationSection = 'overview' | 'forensics' | 'indicators' | 'infrastructure' | 'ai' | 'report';

const NAV_ITEMS: { key: InvestigationSection; label: string; to: string; icon: typeof Crosshair }[] = [
  { key: 'overview', label: 'Overview', to: '/investigation', icon: Crosshair },
  { key: 'forensics', label: 'Forensics', to: '/forensics', icon: FileSearch },
  { key: 'indicators', label: 'Indicators', to: '/indicators', icon: Flag },
  { key: 'infrastructure', label: 'Infrastructure', to: '/infrastructure', icon: Network },
  { key: 'ai', label: 'AI Investigation', to: '/ai-investigation', icon: Brain },
  { key: 'report', label: 'Report', to: '/reports', icon: TrendingUp },
];

interface InvestigationNavigationProps {
  /** The email currently under investigation — carried to every tab via router state
   *  so switching sections never drops back to the table or re-asks for a selection. */
  emailId: string;
  activeSection: InvestigationSection;
}

/**
 * Persistent bottom navigation shown ONLY once a specific email has entered
 * the full investigation workspace (never while merely browsing a table).
 * One shared component — every full-investigation page renders this instead
 * of hand-rolling its own bottom bar, so the markup and behavior never drift.
 */
export function InvestigationNavigation({ emailId, activeSection }: InvestigationNavigationProps) {
  return (
    <div className="sticky bottom-0 w-full border-t border-base-500/25 bg-base-950/90 backdrop-blur-md print:hidden">
      <div className="max-w-[1600px] mx-auto px-8 py-2.5 flex items-center justify-center gap-1.5">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = item.key === activeSection;
          return (
            <Link
              key={item.key}
              to={item.to}
              state={{ emailId }}
              className={cn(
                'flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-[11px] font-semibold uppercase tracking-wider transition-all',
                isActive
                  ? 'text-accent-400 bg-accent-700/10 border border-accent-700/25'
                  : 'text-ink-500 border border-transparent hover:text-ink-200 hover:bg-base-700/40'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {item.label}
            </Link>
          );
        })}
      </div>
    </div>
  );
}
