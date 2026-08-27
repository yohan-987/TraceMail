import { useState, useRef, useEffect, useMemo } from 'react';
import {
  ChevronDown,
  Search,
  AlertTriangle,
  CheckCircle,
  ShieldAlert,
  ShieldX,
  CircleHelp,
  X,
} from 'lucide-react';
import { type ScannedEmail, type EmailStatus } from '@/data/mockData';
import { cn } from '@/lib/utils';

const statusIcon: Record<EmailStatus, typeof AlertTriangle> = {
  safe: CheckCircle,
  suspicious: ShieldAlert,
  malicious: ShieldX,
  inconclusive: CircleHelp,
};

const statusColor: Record<EmailStatus, string> = {
  safe: 'text-emerald-400',
  suspicious: 'text-amber-400',
  malicious: 'text-accent-400',
  inconclusive: 'text-ink-400',
};

const statusDot: Record<EmailStatus, string> = {
  safe: 'bg-emerald-500',
  suspicious: 'bg-amber-500',
  malicious: 'bg-accent-600',
  inconclusive: 'bg-ink-500',
};

interface CaseSelectorProps {
  className?: string;
  /** The email this page currently has selected — local to the page, not global. */
  selected: ScannedEmail | null;
  availableEmails: ScannedEmail[];
  onSelect: (id: string) => void;
  onClear: () => void;
}

export function CaseSelector({ className, selected, availableEmails, onSelect, onClear }: CaseSelectorProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery('');
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();
    if (!q) return availableEmails;
    return availableEmails.filter(
      (e) =>
        e.sender.toLowerCase().includes(q) ||
        e.subject.toLowerCase().includes(q) ||
        e.senderDomain.toLowerCase().includes(q) ||
        e.caseId.toLowerCase().includes(q) ||
        e.id.toLowerCase().includes(q)
    );
  }, [availableEmails, query]);

  const handleSelect = (id: string) => {
    onSelect(id);
    setOpen(false);
    setQuery('');
  };

  const handleClear = () => {
    onClear();
    setOpen(false);
    setQuery('');
  };

  return (
    <div ref={ref} className={cn('relative', className)}>
      {/* Active case card or empty state */}
      {selected ? (
        <button
          onClick={() => setOpen((v) => !v)}
          className={cn(
            'w-full flex items-center gap-4 px-4 py-3 rounded-xl border text-left transition-all',
            open
              ? 'bg-base-700/60 border-accent-700/30'
              : 'bg-base-800/80 border-base-500/40 hover:border-base-400/50'
          )}
        >
          {(() => {
            const Icon = statusIcon[selected.status];
            return <Icon className={cn('w-5 h-5 shrink-0', statusColor[selected.status])} />;
          })()}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-[13px] font-semibold text-ink-100 truncate">{selected.subject}</span>
            </div>
            <div className="flex items-center gap-3 text-[11px] text-ink-500">
              <span className="mono truncate">{selected.sender}</span>
              <span className="shrink-0 text-ink-600">·</span>
              <span className="mono shrink-0">{selected.caseId || selected.id}</span>
              <span className="shrink-0 text-ink-600">·</span>
              <span className="shrink-0">{selected.date}</span>
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <div className="text-right">
              <span className={cn('text-lg font-bold tabular-nums', statusColor[selected.status])}>
                {selected.threatScore}
              </span>
              <span className="text-[9px] text-ink-600 uppercase tracking-wider block leading-none mt-0.5">Score</span>
            </div>
            <ChevronDown className={cn('w-4 h-4 text-ink-500 transition-transform', open && 'rotate-180')} />
          </div>
        </button>
      ) : (
        <button
          onClick={() => setOpen(true)}
          className={cn(
            'w-full flex items-center gap-3 px-4 py-3 rounded-xl border text-left transition-all',
            open
              ? 'bg-base-700/60 border-accent-700/30'
              : 'bg-base-800/80 border-base-500/40 hover:border-base-400/50 border-dashed'
          )}
        >
          <AlertTriangle className="w-5 h-5 text-ink-600 shrink-0" />
          <div className="flex-1">
            <div className="text-[13px] font-semibold text-ink-400">No Case Selected</div>
            <div className="text-[11px] text-ink-600">Click to select an email for investigation</div>
          </div>
          <ChevronDown className={cn('w-4 h-4 text-ink-500 transition-transform', open && 'rotate-180')} />
        </button>
      )}

      {/* Dropdown */}
      {open && (
        <div className="absolute top-full left-0 right-0 mt-2 z-30 rounded-xl border border-base-500/40 bg-base-850 shadow-2xl shadow-black/50 overflow-hidden animate-fade-in">
          {/* Search bar */}
          <div className="flex items-center gap-2 px-3 py-2.5 border-b border-base-500/20">
            <Search className="w-3.5 h-3.5 text-ink-600 shrink-0" />
            <input
              autoFocus
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by sender, subject, domain, case ID..."
              className="flex-1 bg-transparent text-[12px] text-ink-200 placeholder:text-ink-700 focus:outline-none"
            />
            {selected && (
              <button
                onClick={handleClear}
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider text-ink-500 hover:text-accent-400 transition-colors shrink-0"
              >
                <X className="w-2.5 h-2.5" /> Clear
              </button>
            )}
          </div>

          {/* Email list */}
          <div className="max-h-72 overflow-y-auto scrollbar-thin">
            {filtered.length > 0 ? (
              filtered.map((email) => (
                <CaseOption
                  key={email.id}
                  email={email}
                  isSelected={email.id === selected?.id}
                  onSelect={() => handleSelect(email.id)}
                />
              ))
            ) : (
              <div className="py-8 text-center text-[12px] text-ink-600">No emails match your search</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function CaseOption({
  email,
  isSelected,
  onSelect,
}: {
  email: ScannedEmail;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const Icon = statusIcon[email.status];
  return (
    <button
      onClick={onSelect}
      className={cn(
        'w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors border-l-2',
        isSelected
          ? 'bg-accent-700/10 border-l-accent-600'
          : 'hover:bg-base-700/40 border-l-transparent',
        email.status === 'malicious' && !isSelected && 'border-l-accent-700/30',
        email.status === 'suspicious' && !isSelected && 'border-l-amber-700/20',
        email.status === 'safe' && !isSelected && 'border-l-emerald-700/20'
      )}
    >
      <Icon className={cn('w-3.5 h-3.5 shrink-0', statusColor[email.status])} />
      <div className="flex-1 min-w-0">
        <div className="text-[12px] font-medium text-ink-200 truncate">{email.subject}</div>
        <div className="flex items-center gap-2 text-[10px] text-ink-600 mt-0.5">
          <span className="mono truncate">{email.sender}</span>
          <span className="text-ink-700 shrink-0">·</span>
          <span className="mono shrink-0">{email.caseId || email.id}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className={cn('w-1.5 h-1.5 rounded-full', statusDot[email.status])} />
        <span className={cn('text-sm font-bold tabular-nums', statusColor[email.status])}>
          {email.threatScore}
        </span>
      </div>
    </button>
  );
}
