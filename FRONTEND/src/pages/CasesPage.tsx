import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  ArrowDownAZ,
  ArrowUpAZ,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CircleHelp,
  FolderKanban,
  Star,
  Crosshair,
  ArrowRight,
  Radar,
  ShieldQuestion,
} from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { PreviewField } from '@/components/InvestigationWorkspace';
import { mockEmails, type EmailStatus, type ScannedEmail } from '@/data/mockData';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { cn } from '@/lib/utils';

type FilterKey = 'all' | 'safe' | 'suspicious' | 'malicious' | 'inconclusive';
type SortKey = 'score-desc' | 'score-asc' | 'date-desc' | 'date-asc';
type CaseFilter = 'all' | 'none' | string;

const filterTabs: { key: FilterKey; label: string }[] = [
  { key: 'all', label: 'All' },
  { key: 'safe', label: 'Safe' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'malicious', label: 'Malicious' },
  { key: 'inconclusive', label: 'Inconclusive' },
];

const statusIcon: Record<EmailStatus, typeof ShieldCheck> = {
  safe: ShieldCheck,
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

/** Recommended action already exists in the shared dataset — every email's
 *  report includes a RECOMMENDATIONS section. Reused as-is, never invented. */
function getRecommendedAction(email: ScannedEmail): string | null {
  return email.reportSections.find((s) => s.title === 'RECOMMENDATIONS')?.content ?? null;
}

/** Related-email count is computed from the real shared dataset — how many
 *  OTHER emails carry the same non-empty caseId. Honest even when it's 0. */
function getRelatedEmailCount(email: ScannedEmail): number {
  if (!email.caseId) return 0;
  return mockEmails.filter((e) => e.caseId === email.caseId && e.id !== email.id).length;
}

export function CasesPage() {
  const navigate = useNavigate();
  const { lastViewedEmailId, setLastViewed } = useActiveCase();
  const [filter, setFilter] = useState<FilterKey>('all');
  const [caseFilter, setCaseFilter] = useState<CaseFilter>('all');
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('score-desc');
  // Local, Cases-only selection — single click just previews here, exactly
  // like Overview. Cases is a browse+handoff entry point, not a page with
  // its own full-investigation view, so there's nothing here for the shared
  // InvestigationNavigation to attach to — it only appears once Open Case
  // hands off to the Investigation hub.
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);

  const uniqueCaseIds = useMemo(
    () => Array.from(new Set(mockEmails.filter((e) => e.caseId).map((e) => e.caseId))).sort(),
    []
  );

  const selectedEmail = useMemo(
    () => mockEmails.find((e) => e.id === selectedEmailId) ?? null,
    [selectedEmailId]
  );

  const filteredEmails = useMemo(() => {
    let result = mockEmails.filter((email) => {
      const matchesFilter = filter === 'all' || email.status === filter;
      const matchesCase =
        caseFilter === 'all' ? true :
        caseFilter === 'none' ? !email.caseId :
        email.caseId === caseFilter;
      const q = query.toLowerCase().trim();
      const matchesQuery =
        q === '' ||
        email.sender.toLowerCase().includes(q) ||
        email.subject.toLowerCase().includes(q) ||
        email.senderDomain.toLowerCase().includes(q) ||
        email.caseId.toLowerCase().includes(q) ||
        email.id.toLowerCase().includes(q);
      return matchesFilter && matchesCase && matchesQuery;
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
  }, [filter, caseFilter, query, sortKey]);

  // Row click only selects for the inline preview — no navigation.
  const handleSelect = (email: ScannedEmail) => {
    setSelectedEmailId(email.id);
  };

  // Double click / Open Case opens the Investigation Overview/Hub for that
  // email — the same emailId is carried via router state, and the shared
  // InvestigationNavigation bar (already built) takes over from there.
  const handleOpenCase = (email: ScannedEmail) => {
    setLastViewed(email.id);
    navigate('/investigation', { state: { emailId: email.id } });
  };

  return (
    <div className="px-8 py-6 max-w-[1600px] mx-auto">
      <div className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-ink-50">Cases</h1>
          <p className="text-xs text-ink-500 mt-1">Browse all scanned emails by case — an additional entry point, not a prerequisite for investigation</p>
        </div>
      </div>

      {/* Toolbar: filters + case selector + sort + search */}
      <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
        <div className="flex items-center gap-1.5 flex-wrap">
          {filterTabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setFilter(tab.key)}
              className={cn(
                'px-3 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider transition-all',
                filter === tab.key
                  ? 'bg-accent-700/15 text-accent-400 border border-accent-700/25'
                  : 'text-ink-500 hover:text-ink-300 border border-transparent'
              )}
            >
              {tab.label}
            </button>
          ))}
          <div className="w-px h-4 bg-base-500/30 mx-1" />

          {/* Case ID filter/selector */}
          <div className="relative">
            <select
              value={caseFilter}
              onChange={(e) => setCaseFilter(e.target.value)}
              className="appearance-none pl-7 pr-6 py-1.5 rounded-md text-[10px] font-semibold uppercase tracking-wider bg-base-800/60 border border-base-500/25 text-ink-300 focus:outline-none focus:border-accent-700/30 cursor-pointer"
            >
              <option value="all">All Cases</option>
              <option value="none">No Case</option>
              {uniqueCaseIds.map((id) => (
                <option key={id} value={id}>{id}</option>
              ))}
            </select>
            <FolderKanban className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-ink-600 pointer-events-none" />
          </div>

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
            placeholder="Search sender, subject, case ID..."
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-base-800/60 border border-base-500/25 text-[12px] text-ink-200 placeholder:text-ink-700 focus:outline-none focus:border-accent-700/30 transition-colors"
          />
        </div>
      </div>

      {/* Table + inline preview */}
      <div className="grid grid-cols-12 gap-5">
        <div className="col-span-8">
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px]">
                <thead>
                  <tr className="border-b border-base-500/20">
                    <Th>Case ID</Th>
                    <Th>Email ID</Th>
                    <Th>Status</Th>
                    <Th>Sender</Th>
                    <Th>Subject</Th>
                    <Th>Score</Th>
                    <Th>Classification</Th>
                    <Th>Date / Time</Th>
                    <Th className="text-center">Last Viewed</Th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEmails.map((email) => (
                    <CaseRow
                      key={email.id}
                      email={email}
                      isSelected={email.id === selectedEmailId}
                      isLastViewed={email.id === lastViewedEmailId}
                      onSelect={() => handleSelect(email)}
                      onOpenCase={() => handleOpenCase(email)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
            {filteredEmails.length === 0 && (
              <div className="py-16 text-center">
                <FolderKanban className="w-6 h-6 text-ink-700 mx-auto mb-3" />
                <p className="text-sm text-ink-600">No emails match this case filter or search</p>
              </div>
            )}
          </Card>
        </div>

        <div className="col-span-4">
          <Card className="sticky top-6 p-5 min-h-[420px] flex flex-col">
            {selectedEmail ? (
              <div key={selectedEmail.id} className="animate-fade-in">
                <CasePreview email={selectedEmail} onOpenCase={() => handleOpenCase(selectedEmail)} />
              </div>
            ) : (
              <div className="h-full flex-1 flex flex-col items-center justify-center text-center px-4">
                <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-base-800 border border-base-500/30 mb-4">
                  <FolderKanban className="w-5 h-5 text-ink-600" />
                </div>
                <h3 className="text-sm font-semibold text-ink-300">No Email Selected</h3>
                <p className="text-[11px] text-ink-600 mt-1.5 max-w-[220px] leading-relaxed">
                  Click any row for a quick case summary. Use Open Case for the full investigation.
                </p>
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

function CaseRow({
  email,
  isSelected,
  isLastViewed,
  onSelect,
  onOpenCase,
}: {
  email: ScannedEmail;
  isSelected: boolean;
  isLastViewed: boolean;
  onSelect: () => void;
  onOpenCase: () => void;
}) {
  const Icon = statusIcon[email.status];
  const rowAccent = isSelected ? 'border-l-2 border-l-accent-500' : 'border-l-2 border-l-transparent';

  return (
    <tr
      onClick={onSelect}
      onDoubleClick={onOpenCase}
      className={cn(
        'border-b border-base-500/10 hover:bg-base-700/30 transition-colors cursor-pointer group',
        isSelected && 'bg-base-700/40',
        rowAccent
      )}
    >
      <td className="pl-5 py-3">
        <span className="mono text-[11px] text-ink-400">{email.caseId || '—'}</span>
      </td>
      <td>
        <span className="mono text-[11px] text-ink-500">{email.id}</span>
      </td>
      <td>
        <div className="flex items-center gap-1.5">
          <Icon className={cn('w-3.5 h-3.5', statusColor[email.status])} />
          <span className={cn('text-[10px] font-semibold uppercase tracking-wider', statusColor[email.status])}>
            {email.status}
          </span>
        </div>
      </td>
      <td>
        <span className="text-[12px] text-ink-200 truncate max-w-[160px] block">{email.sender}</span>
      </td>
      <td>
        <span className="text-[12px] text-ink-300 truncate max-w-[220px] block">{email.subject}</span>
      </td>
      <td>
        <span className={cn('text-[13px] font-bold tabular-nums', statusColor[email.status])}>{email.threatScore}</span>
      </td>
      <td>
        <span className="text-[11px] text-ink-400">{email.classification}</span>
      </td>
      <td>
        <span className="mono text-[10px] text-ink-500">{email.date}</span>
      </td>
      <td className="text-center pr-5">
        {isLastViewed && <Star className="w-3.5 h-3.5 text-accent-500 fill-accent-500 inline" />}
      </td>
    </tr>
  );
}

function CasePreview({ email, onOpenCase }: { email: ScannedEmail; onOpenCase: () => void }) {
  const Icon = statusIcon[email.status];
  const relatedCount = getRelatedEmailCount(email);
  const recommendedAction = getRecommendedAction(email);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Case Summary</SectionLabel>
        <Badge variant={email.threatScore >= 60 ? 'danger' : 'neutral'}>{email.classification}</Badge>
      </div>

      <div className="flex items-start gap-3 mb-4">
        <Icon className={cn('w-5 h-5 mt-0.5 shrink-0', statusColor[email.status])} />
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug">{email.subject}</div>
          <div className="mono text-[10px] text-ink-500 mt-1">{email.sender}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2.5 mb-4">
        <PreviewField label="Case ID" value={email.caseId || 'No Case'} mono />
        <PreviewField label="Email ID" value={email.id} mono />
        <PreviewField label="Status" value={email.status} valueClassName={statusColor[email.status]} />
        <PreviewField
          label="Threat Score"
          value={String(email.threatScore)}
          valueClassName={email.threatScore >= 60 ? 'text-accent-400' : 'text-emerald-400'}
        />
      </div>

      {email.whyFlagged.length > 0 && (
        <>
          <SectionLabel className="block mb-2.5">Main Evidence</SectionLabel>
          <ul className="space-y-1.5 mb-4">
            {email.whyFlagged.slice(0, 3).map((reason, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] text-ink-400 leading-relaxed">
                <span className="mono text-[9px] text-accent-600 mt-0.5 shrink-0">{String(i + 1).padStart(2, '0')}</span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <div className="panel-2 p-3 mb-4">
        <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Related Emails In Case</div>
        <div className="text-[12px] text-ink-200">
          {email.caseId
            ? `${relatedCount} other email${relatedCount === 1 ? '' : 's'} in ${email.caseId}`
            : 'Not part of a case'}
        </div>
      </div>

      {recommendedAction && (
        <div className="panel-2 p-3 mb-4">
          <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">Recommended Action</div>
          <div className="text-[11px] text-ink-300 leading-relaxed whitespace-pre-line line-clamp-4">{recommendedAction}</div>
        </div>
      )}

      {/* Forward-compatible campaign correlation — nothing here is fabricated;
          the mock dataset has no cross-email correlation model yet, so every
          field below is explicitly UNAVAILABLE until the backend provides it. */}
      <div className="panel-2 p-3 mb-4">
        <div className="flex items-center gap-1.5 mb-2">
          <Radar className="w-3 h-3 text-sky-400" />
          <span className="text-[9px] font-semibold uppercase tracking-wider text-ink-500">Likely Related Campaign</span>
        </div>
        <div className="space-y-1.5">
          <CampaignField label="Campaign ID" />
          <CampaignField label="Shared Indicators" />
          <CampaignField label="Shared Infrastructure" />
          <CampaignField label="Correlation Confidence" />
        </div>
      </div>

      <Divider className="mb-4" />

      <button
        onClick={onOpenCase}
        className="mt-auto flex items-center justify-center gap-2 w-full py-2.5 rounded-lg text-[11px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors"
      >
        <Crosshair className="w-3.5 h-3.5" /> Open Case <ArrowRight className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

function CampaignField({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[10px] text-ink-600">{label}</span>
      <span className="text-[10px] text-ink-600 italic flex items-center gap-1">
        <ShieldQuestion className="w-2.5 h-2.5" /> UNAVAILABLE
      </span>
    </div>
  );
}

function Th({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <th className={cn('text-left py-2.5 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink-600 whitespace-nowrap', className)}>
      {children}
    </th>
  );
}
