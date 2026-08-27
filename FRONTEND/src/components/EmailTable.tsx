import { useState, useMemo, useRef } from 'react';
import {
  Search,
  Star,
  ArrowDownAZ,
  ArrowUpAZ,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Inbox,
  FolderKanban,
} from 'lucide-react';
import { SectionLabel, Badge } from '@/components/ui/Primitives';
import { mockEmails, type ScannedEmail, type EmailStatus } from '@/data/mockData';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { cn } from '@/lib/utils';

type SortKey = 'score-desc' | 'score-asc' | 'date-desc' | 'date-asc';
type StatusFilter = 'all' | 'clean' | 'suspicious' | 'threats';
type CaseFilter = 'all' | 'none' | string;

const statusConfig: Record<EmailStatus, { dot: string; text: string }> = {
  safe: { dot: 'bg-emerald-500', text: 'text-emerald-400' },
  suspicious: { dot: 'bg-amber-500', text: 'text-amber-400' },
  malicious: { dot: 'bg-accent-600', text: 'text-accent-400' },
  inconclusive: { dot: 'bg-ink-500', text: 'text-ink-400' },
};

const filterTabs: { key: StatusFilter; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'clean', label: 'Clean' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'threats', label: 'Threats' },
];

interface EmailTableProps {
  selectedId: string | null;
  onSelect: (email: ScannedEmail) => void;
  onInvestigate: (email: ScannedEmail) => void;
  /** Opt-in only — Forensics/Indicators/Infrastructure don't pass this and
   *  are completely unaffected. Reports (and any future case-centric page)
   *  can enable it to add a Case ID filter dropdown to this same table. */
  enableCaseFilter?: boolean;
}

export function EmailTable({ selectedId, onSelect, onInvestigate, enableCaseFilter }: EmailTableProps) {
  const { lastViewedEmailId, lastViewedEmail } = useActiveCase();
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [caseFilter, setCaseFilter] = useState<CaseFilter>('all');
  const [sortKey, setSortKey] = useState<SortKey>('score-desc');
  const [page, setPage] = useState(0);
  const pageSize = 50;
  const clickTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const uniqueCaseIds = useMemo(
    () => Array.from(new Set(mockEmails.filter((e) => e.caseId).map((e) => e.caseId))).sort(),
    []
  );

  const filtered = useMemo(() => {
    let result = mockEmails.filter((email) => {
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'clean' && email.status === 'safe') ||
        (statusFilter === 'suspicious' && email.status === 'suspicious') ||
        (statusFilter === 'threats' && email.status === 'malicious');
      const matchesCase =
        !enableCaseFilter || caseFilter === 'all'
          ? true
          : caseFilter === 'none'
          ? !email.caseId
          : email.caseId === caseFilter;
      const q = query.toLowerCase().trim();
      const matchesQuery =
        q === '' ||
        email.sender.toLowerCase().includes(q) ||
        email.subject.toLowerCase().includes(q) ||
        email.senderDomain.toLowerCase().includes(q) ||
        email.caseId.toLowerCase().includes(q) ||
        email.id.toLowerCase().includes(q) ||
        email.classification.toLowerCase().includes(q);
      return matchesStatus && matchesCase && matchesQuery;
    });

    result = [...result].sort((a, b) => {
      switch (sortKey) {
        case 'score-desc': return b.threatScore - a.threatScore;
        case 'score-asc': return a.threatScore - b.threatScore;
        case 'date-desc': return b.date.localeCompare(a.date);
        case 'date-asc': return a.date.localeCompare(b.date);
      }
    });

    return result;
  }, [query, statusFilter, caseFilter, enableCaseFilter, sortKey]);

  const totalPages = Math.ceil(filtered.length / pageSize);
  const currentPage = Math.min(page, Math.max(0, totalPages - 1));
  const pageEmails = filtered.slice(currentPage * pageSize, (currentPage + 1) * pageSize);

  const handleRowClick = (email: ScannedEmail) => {
    if (clickTimer.current) {
      clearTimeout(clickTimer.current);
      clickTimer.current = null;
      onInvestigate(email);
    } else {
      clickTimer.current = setTimeout(() => {
        onSelect(email);
        clickTimer.current = null;
      }, 220);
    }
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header */}
      <div className="px-4 py-3 border-b border-base-500/30 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Inbox className="w-3.5 h-3.5 text-accent-500" />
            <SectionLabel>Email Inbox</SectionLabel>
          </div>
          <span className="text-[9px] text-ink-600 mono">{filtered.length} emails</span>
        </div>

        {/* Search */}
        <div className="relative mb-2.5">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-ink-600" />
          <input
            value={query}
            onChange={(e) => { setQuery(e.target.value); setPage(0); }}
            placeholder="Search..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-base-950/60 border border-base-500/25 text-[11px] text-ink-200 placeholder:text-ink-700 focus:outline-none focus:border-accent-700/30 transition-colors"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center gap-1 mb-2 flex-wrap">
          {filterTabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => { setStatusFilter(tab.key); setPage(0); }}
              className={cn(
                'px-2 py-1 rounded text-[9px] font-semibold uppercase tracking-wider transition-all',
                statusFilter === tab.key
                  ? 'bg-accent-700/15 text-accent-400 border border-accent-700/25'
                  : 'text-ink-600 hover:text-ink-400 border border-transparent'
              )}
            >
              {tab.label}
            </button>
          ))}

          {enableCaseFilter && (
            <div className="relative ml-1">
              <select
                value={caseFilter}
                onChange={(e) => { setCaseFilter(e.target.value); setPage(0); }}
                className="appearance-none pl-6 pr-5 py-1 rounded text-[9px] font-semibold uppercase tracking-wider bg-base-950/60 border border-base-500/25 text-ink-400 focus:outline-none focus:border-accent-700/30 cursor-pointer"
              >
                <option value="all">All Cases</option>
                <option value="none">No Case</option>
                {uniqueCaseIds.map((id) => (
                  <option key={id} value={id}>{id}</option>
                ))}
              </select>
              <FolderKanban className="absolute left-1.5 top-1/2 -translate-y-1/2 w-2.5 h-2.5 text-ink-600 pointer-events-none" />
            </div>
          )}
        </div>

        {/* Sort */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => setSortKey(sortKey === 'score-desc' ? 'score-asc' : 'score-desc')}
            className={cn(
              'flex items-center gap-1 px-2 py-1 rounded text-[9px] font-semibold uppercase tracking-wider transition-all',
              sortKey.startsWith('score') ? 'text-accent-400 bg-accent-700/10' : 'text-ink-600 hover:text-ink-400'
            )}
          >
            Score {sortKey === 'score-asc' ? <ArrowUpAZ className="w-2.5 h-2.5" /> : <ArrowDownAZ className="w-2.5 h-2.5" />}
          </button>
          <button
            onClick={() => setSortKey(sortKey === 'date-desc' ? 'date-asc' : 'date-desc')}
            className={cn(
              'flex items-center gap-1 px-2 py-1 rounded text-[9px] font-semibold uppercase tracking-wider transition-all',
              sortKey.startsWith('date') ? 'text-accent-400 bg-accent-700/10' : 'text-ink-600 hover:text-ink-400'
            )}
          >
            Date {sortKey === 'date-asc' ? <ArrowUpAZ className="w-2.5 h-2.5" /> : <ArrowDownAZ className="w-2.5 h-2.5" />}
          </button>
        </div>
      </div>

      {/* Email list - scrollable */}
      <div className="flex-1 overflow-y-auto scrollbar-thin min-h-0">
        {/* Last viewed pinned section */}
        {lastViewedEmail && (
          <div className="border-b border-base-500/20">
            <div className="px-4 py-1.5 bg-base-900/40 flex items-center gap-1.5">
              <Star className="w-2.5 h-2.5 text-accent-500" />
              <span className="text-[8px] font-bold uppercase tracking-[0.15em] text-accent-500">Last Viewed</span>
            </div>
            <EmailTableRow
              email={lastViewedEmail}
              isSelected={selectedId === lastViewedEmail.id}
              onClick={() => handleRowClick(lastViewedEmail)}
            />
          </div>
        )}

        {/* All emails */}
        <div className="px-4 py-1.5 bg-base-900/20 flex items-center gap-1.5 sticky top-0 z-10">
          <span className="text-[8px] font-bold uppercase tracking-[0.15em] text-ink-500">All Emails</span>
        </div>
        {pageEmails.map((email) => (
          <EmailTableRow
            key={email.id}
            email={email}
            isSelected={selectedId === email.id}
            onClick={() => handleRowClick(email)}
          />
        ))}
        {pageEmails.length === 0 && (
          <div className="py-12 text-center">
            <Inbox className="w-5 h-5 text-ink-700 mx-auto mb-2" />
            <p className="text-[11px] text-ink-600">No emails match</p>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-2 border-t border-base-500/30 shrink-0">
          <button
            disabled={currentPage === 0}
            onClick={() => setPage(currentPage - 1)}
            className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 disabled:text-ink-700 hover:text-accent-400 transition-colors"
          >
            Prev
          </button>
          <span className="text-[9px] text-ink-600 mono">{currentPage + 1} / {totalPages}</span>
          <button
            disabled={currentPage >= totalPages - 1}
            onClick={() => setPage(currentPage + 1)}
            className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 disabled:text-ink-700 hover:text-accent-400 transition-colors"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

function EmailTableRow({ email, isSelected, onClick }: { email: ScannedEmail; isSelected: boolean; onClick: () => void }) {
  const config = statusConfig[email.status];
  const scoreColor =
    email.threatScore >= 80 ? 'text-accent-500' :
    email.threatScore >= 60 ? 'text-amber-400' :
    email.threatScore >= 35 ? 'text-ink-400' :
    'text-emerald-400';

  return (
    <div
      onClick={onClick}
      className={cn(
        'px-4 py-2.5 border-b border-base-500/10 cursor-pointer transition-colors border-l-2',
        isSelected
          ? 'bg-accent-700/10 border-l-accent-600'
          : email.status === 'malicious'
          ? 'border-l-accent-700/30 hover:bg-base-700/30'
          : email.status === 'suspicious'
          ? 'border-l-amber-700/20 hover:bg-base-700/30'
          : 'border-l-transparent hover:bg-base-700/30'
      )}
    >
      <div className="flex items-start justify-between gap-2 mb-1">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', config.dot)} />
          <span className="text-[11px] font-medium text-ink-200 truncate">{email.senderName}</span>
        </div>
        <span className={cn('text-sm font-bold tabular-nums shrink-0', scoreColor)}>{email.threatScore}</span>
      </div>
      <div className="text-[11px] text-ink-400 truncate mb-0.5">{email.subject}</div>
      <div className="flex items-center gap-2 text-[9px] text-ink-600">
        <span className="mono truncate">{email.caseId || email.id}</span>
        <span className="shrink-0">·</span>
        <span className="shrink-0">{email.classification}</span>
        <span className="shrink-0">·</span>
        <span className="mono shrink-0">{email.date}</span>
      </div>
    </div>
  );
}

export { statusConfig };

export function StatusIcon({ status, className }: { status: EmailStatus; className?: string }) {
  const icons = { safe: ShieldCheck, suspicious: ShieldAlert, malicious: ShieldX, inconclusive: Inbox };
  const Icon = icons[status];
  return <Icon className={className} />;
}
