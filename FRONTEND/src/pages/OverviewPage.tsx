import { useState, useMemo, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Inbox,
  TrendingUp,
  FileText,
  ArrowDownAZ,
  ArrowUpAZ,
} from 'lucide-react';
import { Card, SectionLabel, Badge } from '@/components/ui/Primitives';
import { EmailPreview } from '@/components/InvestigationWorkspace';
import { type EmailStatus, type ScannedEmail } from '@/types/email';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { cn } from '@/lib/utils';
import { getEmails } from '@/api/api';
import { mapApiEmailToUiEmail } from '@/api/emailMapper';

type FilterKey = 'all' | 'safe' | 'suspicious' | 'malicious' | 'inconclusive';
type SortKey = 'score-desc' | 'score-asc' | 'date-desc' | 'date-asc';

const filterTabs: { key: FilterKey; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'safe', label: 'Safe' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'malicious', label: 'Malicious' },
  { key: 'inconclusive', label: 'Inconclusive' },
];

const statusConfig: Record<EmailStatus, { label: string; dot: string; text: string; badgeVariant: 'neutral' | 'warning' | 'danger' | 'active' }> = {
  safe: { label: 'Safe', dot: 'bg-emerald-500', text: 'text-emerald-400', badgeVariant: 'neutral' },
  suspicious: { label: 'Suspicious', dot: 'bg-amber-500', text: 'text-amber-400', badgeVariant: 'warning' },
  malicious: { label: 'Malicious', dot: 'bg-accent-600', text: 'text-accent-400', badgeVariant: 'danger' },
  inconclusive: { label: 'Inconclusive', dot: 'bg-ink-500', text: 'text-ink-400', badgeVariant: 'neutral' },
};

export function OverviewPage() {
  const navigate = useNavigate();
  const { setLastViewed } = useActiveCase();
  const [filter, setFilter] = useState<FilterKey>('all');
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('score-desc');
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);

// --- LIVE API STATE ---
const [apiEmails, setApiEmails] = useState<ScannedEmail[]>([]);
const [totalEmails, setTotalEmails] = useState(0);
const [isLoading, setIsLoading] = useState(true);
const [error, setError] = useState<string | null>(null);

// --- FETCH DATA ON LOAD ---
useEffect(() => {
  getEmails({ limit: 200, sort: 'date' })
    .then((response) => {
      const mappedData = response.items.map(mapApiEmailToUiEmail);
      setApiEmails(mappedData);
      setTotalEmails(response.pagination.total);
    })
    .catch((err) =>
      setError(err instanceof Error ? err.message : 'Failed to load emails')
    )
    .finally(() => setIsLoading(false));
}, []);
// --- CALCULATE STATS FROM REAL DATA ---
const stats = useMemo(() => ({
  total: totalEmails,
  safe: apiEmails.filter((e) => e.status === 'safe').length,
  suspicious: apiEmails.filter((e) => e.status === 'suspicious').length,
  malicious: apiEmails.filter((e) => e.status === 'malicious').length,
  inconclusive: apiEmails.filter((e) => e.status === 'inconclusive').length,
}), [apiEmails, totalEmails]);

  // --- SELECT FROM REAL DATA ---
  const selectedEmail = useMemo(
    () => apiEmails.find((e) => e.id === selectedEmailId) ?? null,
    [apiEmails, selectedEmailId]
  );

  // --- FILTER AND SORT LOGIC ---
  const filteredEmails = useMemo(() => {
    let result = apiEmails.filter((email) => {
      const matchesFilter = filter === 'all' || email.status === filter;
      const q = query.toLowerCase().trim();
      
      const matchesQuery =
        q === '' ||
        email.sender.toLowerCase().includes(q) ||
        email.senderDomain.toLowerCase().includes(q) ||
        email.subject.toLowerCase().includes(q) ||
        email.recipient.toLowerCase().includes(q) ||
        (email.caseId ?? '').toLowerCase().includes(q) ||
        email.id.toLowerCase().includes(q);
        
      return matchesFilter && matchesQuery;
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
  }, [apiEmails, filter, query, sortKey]);

  const handleSelect = (email: ScannedEmail) => {
    setSelectedEmailId(email.id);
  };

  const handleInspect = (email: ScannedEmail) => {
    setLastViewed(email.id);
    navigate('/investigation', { state: { emailId: email.id } });
  };

  const handleReport = (email: ScannedEmail) => {
    setLastViewed(email.id);
    navigate('/reports', { state: { emailId: email.id } });
  };

  // --- LOADING / ERROR STATES ---
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-[600px] w-full text-ink-300 font-mono text-sm">
        Fetching live data from backend...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-[600px] w-full text-accent-500 font-mono text-sm">
        Error loading emails: {error}
      </div>
    );
  }

  return (
    <div className="px-8 py-6 max-w-[1600px] mx-auto">
      <div className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-ink-50">Email Security Dashboard</h1>
          <p className="text-xs text-ink-500 mt-1">Triage and prioritize threats across all scanned emails</p>
        </div>
        <div className="flex items-center gap-2 text-[10px] text-ink-600">
          <span className="mono">Live API Connection</span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <MetricCard icon={Inbox} label="Total Scanned" value={stats.total} />
        <MetricCard icon={ShieldCheck} label="Clean / Safe" value={stats.safe} variant="success" />
        <MetricCard icon={ShieldAlert} label="Suspicious" value={stats.suspicious} variant="warning" />
        <MetricCard icon={ShieldX} label="Critical Threats" value={stats.malicious} variant="danger" />
      </div>

      <div className="flex items-center gap-2 mb-3">
        <TrendingUp className="w-3.5 h-3.5 text-accent-500" />
        <SectionLabel>Email Triage &amp; Analysis</SectionLabel>
        <span className="text-[10px] text-ink-600 ml-auto">{filteredEmails.length} of {stats.total} emails</span>
      </div>

      <div className="flex items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-1.5">
          {filterTabs.map((tab) => {
            const count =
              tab.key === 'all' ? stats.total :
              tab.key === 'safe' ? stats.safe :
              tab.key === 'suspicious' ? stats.suspicious :
              tab.key === 'malicious' ? stats.malicious :
              stats.inconclusive; 
            return (
              <button
                key={tab.key}
                onClick={() => setFilter(tab.key)}
                className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider transition-all',
                  filter === tab.key
                    ? 'bg-accent-700/15 text-accent-400 border border-accent-700/25'
                    : 'text-ink-500 hover:text-ink-300 border border-transparent'
                )}
              >
                {tab.label}
                <span className="text-[9px] text-ink-600 tabular-nums">{count}</span>
              </button>
            );
          })}
          <div className="w-px h-4 bg-base-500/30 mx-1" />
          <button
            onClick={() => setSortKey(sortKey === 'score-desc' ? 'score-asc' : 'score-desc')}
            className={cn(
              'flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-semibold uppercase tracking-wider transition-all',
              sortKey.startsWith('score') ? 'text-accent-400 bg-accent-700/10' : 'text-ink-600 hover:text-ink-400'
            )}
          >
            Score {sortKey === 'score-asc' ? <ArrowUpAZ className="w-2.5 h-2.5" /> : <ArrowDownAZ className="w-2.5 h-2.5" />}
          </button>
          <button
            onClick={() => setSortKey(sortKey === 'date-desc' ? 'date-asc' : 'date-desc')}
            className={cn(
              'flex items-center gap-1 px-2.5 py-1.5 rounded-md text-[10px] font-semibold uppercase tracking-wider transition-all',
              sortKey.startsWith('date') ? 'text-accent-400 bg-accent-700/10' : 'text-ink-600 hover:text-ink-400'
            )}
          >
            Date {sortKey === 'date-asc' ? <ArrowUpAZ className="w-2.5 h-2.5" /> : <ArrowDownAZ className="w-2.5 h-2.5" />}
          </button>
        </div>
        <div className="relative w-72">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search sender, subject, domain, case ID..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-base-800/60 border border-base-500/25 text-[12px] text-ink-200 placeholder:text-ink-700 focus:outline-none focus:border-accent-700/30 transition-colors"
          />
        </div>
      </div>

      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-8">
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px]">
                <thead>
                  <tr className="border-b border-base-500/20">
                    <Th>Status</Th>
                    <Th>Sender &amp; Domain</Th>
                    <Th>Subject</Th>
                    <Th>Recipient</Th>
                    <Th>Score</Th>
                    <Th>Classification</Th>
                    <Th>Date / Time</Th>
                    <Th className="text-right pr-5">Action</Th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEmails.map((email) => (
                    <EmailRow
                      key={email.id}
                      email={email}
                      isSelected={email.id === selectedEmailId}
                      onSelect={() => handleSelect(email)}
                      onInspect={() => handleInspect(email)}
                      onReport={() => handleReport(email)}
                      onDoubleClick={() => handleInspect(email)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            {filteredEmails.length === 0 && (
              <div className="py-16 text-center">
                <Inbox className="w-6 h-6 text-ink-700 mx-auto mb-3" />
                <p className="text-sm text-ink-600">No emails match your search or filter</p>
              </div>
            )}
          </Card>
        </div>

        <div className="col-span-4">
          <Card className="sticky top-6 p-5 min-h-[420px] flex flex-col">
            {selectedEmail ? (
              <div key={selectedEmail.id} className="animate-fade-in">
                <EmailPreview
                  email={selectedEmail}
                  investigateLabel="Inspect"
                  onInvestigate={() => handleInspect(selectedEmail)}
                  onReport={() => handleReport(selectedEmail)}
                />
              </div>
            ) : (
              <div className="h-full flex-1 flex flex-col items-center justify-center text-center px-4">
                <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-base-800 border border-base-500/30 mb-4">
                  <Search className="w-5 h-5 text-ink-600" />
                </div>
                <h3 className="text-sm font-semibold text-ink-300">No Email Selected</h3>
                <p className="text-[11px] text-ink-600 mt-1.5 max-w-[220px] leading-relaxed">
                  Click any email in the table for a quick summary. Use Inspect for the full investigation.
                </p>
              </div>
            )}
          </Card>
        </div>
      </div>

      <div className="mt-5 flex items-center justify-center gap-2 text-[10px] text-ink-600 uppercase tracking-wider">
        <span className="text-ink-500 font-semibold">Triage</span>
        <span>→</span>
        <span>Identify Threats</span>
        <span>→</span>
        <span>Select Case</span>
        <span>→</span>
        <span>Forensic Investigation</span>
        <span>→</span>
        <span>Report</span>
      </div>
    </div>
  );
}

function EmailRow({
  email,
  isSelected,
  onSelect,
  onInspect,
  onReport,
  onDoubleClick,
}: {
  email: ScannedEmail;
  isSelected: boolean;
  onSelect: () => void;
  onInspect: () => void;
  onReport: () => void;
  onDoubleClick?: () => void;
}) {
  const config = statusConfig[email.status];
  const scoreColor =
    email.threatScore >= 80 ? 'text-accent-500' :
    email.threatScore >= 60 ? 'text-amber-400' :
    email.threatScore >= 35 ? 'text-ink-400' :
    'text-emerald-400';

  const rowAccent = isSelected
    ? 'border-l-2 border-l-accent-500'
    : email.status === 'malicious' ? 'border-l-2 border-l-accent-700/40' :
      email.status === 'suspicious' ? 'border-l-2 border-l-amber-700/30' :
      email.status === 'inconclusive' ? 'border-l-2 border-l-ink-600/30' :
      'border-l-2 border-l-transparent';

  return (
    <tr
      onClick={onSelect}
      onDoubleClick={onDoubleClick}
      className={cn(
        'border-b border-base-500/10 hover:bg-base-700/30 transition-colors cursor-pointer group',
        isSelected && 'bg-base-700/40',
        rowAccent
      )}
    >
      <td className="pl-4 py-3">
        <div className="flex items-center gap-2">
          <span className={cn('w-1.5 h-1.5 rounded-full', config.dot)} />
          <span className={cn('text-[11px] font-semibold uppercase tracking-wider', config.text)}>
            {config.label}
          </span>
        </div>
      </td>
      <td>
        <div className="flex flex-col">
          <span className="text-[12px] text-ink-200 truncate max-w-[200px]">{email.senderName}</span>
          <span className="mono text-[10px] text-ink-500 truncate max-w-[200px]">{email.sender}</span>
          <span className="mono text-[9px] text-ink-700 truncate max-w-[200px] mt-0.5">{email.senderDomain}</span>
        </div>
      </td>
      <td>
        <span className="text-[12px] text-ink-300 truncate max-w-[280px] block">{email.subject}</span>
      </td>
      <td>
        <span className="mono text-[11px] text-ink-500">{email.recipient}</span>
      </td>
      <td>
        <span className={cn('text-lg font-bold tabular-nums', scoreColor)}>{email.threatScore}</span>
      </td>
      <td>
        <Badge variant={config.badgeVariant}>{email.classification}</Badge>
      </td>
      <td>
        <span className="mono text-[11px] text-ink-500 whitespace-nowrap">{email.date}</span>
      </td>
      <td className="pr-5 text-right">
        <div className="flex items-center justify-end gap-1.5">
          <button
            onClick={(e) => { e.stopPropagation(); onReport(); }}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-semibold uppercase tracking-wider text-ink-500 hover:text-ink-200 hover:bg-base-700/50 transition-all"
          >
            <FileText className="w-2.5 h-2.5" /> Report
          </button>
          <button
            onClick={(e) => { e.stopPropagation(); onInspect(); }}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[10px] font-semibold uppercase tracking-wider text-ink-500 group-hover:text-accent-400 group-hover:bg-accent-700/10 transition-all"
          >
            Inspect <ArrowRight className="w-2.5 h-2.5" />
          </button>
        </div>
      </td>
    </tr>
  );
}

function MetricCard({ icon: Icon, label, value, variant }: { icon: typeof Inbox; label: string; value: number; variant?: 'success' | 'warning' | 'danger' }) {
  const colorClass = variant === 'danger' ? 'text-accent-500' : variant === 'warning' ? 'text-amber-400' : variant === 'success' ? 'text-emerald-400' : 'text-ink-100';
  const iconColor = variant === 'danger' ? 'text-accent-600' : variant === 'warning' ? 'text-amber-600' : variant === 'success' ? 'text-emerald-600' : 'text-ink-600';
  return (
    <Card className="p-4 flex items-center justify-between">
      <div>
        <div className={cn('text-3xl font-bold tabular-nums', colorClass)}>{value}</div>
        <div className="section-label mt-1">{label}</div>
      </div>
      <Icon className={cn('w-5 h-5', iconColor)} />
    </Card>
  );
}

function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={cn('text-left py-2.5 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink-600 whitespace-nowrap', className)}>
      {children}
    </th>
  );
}