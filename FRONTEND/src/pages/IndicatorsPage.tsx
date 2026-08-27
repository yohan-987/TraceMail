import { useState, useMemo } from 'react';
import { useLocation } from 'react-router-dom';
import { Flag, Search, Filter, Globe, Link2, Hash, Mail, Server, X, ShieldQuestion } from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { InvestigationShell } from '@/components/InvestigationShell';
import {
  InvestigationWorkspace,
  PreviewField,
  PreviewInvestigateButton,
} from '@/components/InvestigationWorkspace';
import type { ScannedEmail, ThreatIndicator } from '@/data/mockData';
import { cn } from '@/lib/utils';

const IOC_TYPES = ['IP', 'Domain', 'URL', 'Hash', 'Email'] as const;
type IocType = (typeof IOC_TYPES)[number];

const typeFilters = ['ALL', ...IOC_TYPES] as const;
const typeIcons: Record<string, typeof Globe> = {
  IP: Server,
  Domain: Globe,
  URL: Link2,
  Hash: Hash,
  Email: Mail,
};
const typeSectionLabel: Record<IocType, string> = {
  IP: 'IP Addresses',
  Domain: 'Domains',
  URL: 'URLs',
  Hash: 'Hashes',
  Email: 'Email Addresses',
};

/**
 * The mock dataset only carries a raw reputation enum. This maps it onto the
 * doc's actual status vocabulary — no new judgment is introduced, "unknown"
 * (no intel present) becomes "Unavailable" rather than being hidden or guessed at.
 */
function statusLabel(rep: ThreatIndicator['reputation']): string {
  switch (rep) {
    case 'malicious': return 'Malicious';
    case 'suspicious': return 'Suspicious';
    case 'clean': return 'Verified';
    case 'unknown': return 'Unavailable';
  }
}

function statusColor(rep: ThreatIndicator['reputation']): string {
  switch (rep) {
    case 'malicious': return 'text-accent-400';
    case 'suspicious': return 'text-amber-400';
    case 'clean': return 'text-emerald-400';
    case 'unknown': return 'text-ink-500';
  }
}

function statusDot(rep: ThreatIndicator['reputation']): string {
  switch (rep) {
    case 'malicious': return 'bg-accent-600';
    case 'suspicious': return 'bg-amber-500';
    case 'clean': return 'bg-emerald-500';
    case 'unknown': return 'bg-ink-600';
  }
}

const severityRank: Record<ThreatIndicator['reputation'], number> = {
  malicious: 0, suspicious: 1, clean: 2, unknown: 3,
};

interface DetailField {
  label: string;
  value: string | null;
}

/**
 * Builds the IOC detail-drawer field set. Every field is either pulled
 * directly from existing data (the shared indicator record, or the email's
 * existing geoData for IPs) or deterministically parsed from the IOC's own
 * value (TLD, hostname, HTTPS, path depth). Nothing here is invented threat
 * intelligence — anything the backend hasn't supplied yet is `null` and
 * renders as UNAVAILABLE, ready to be filled in by GET /api/v1/emails/:emailId.
 */
function getIocDetailFields(ioc: ThreatIndicator, email: ScannedEmail): DetailField[] {
  if (ioc.type === 'IP') {
    const geo = email.geoData.find((g) => g.ip === ioc.value);
    return [
      { label: 'Address', value: ioc.value },
      { label: 'Classification', value: statusLabel(ioc.reputation) },
      { label: 'Country', value: geo?.country ?? null },
      { label: 'Region', value: null },
      { label: 'City', value: geo?.city ?? null },
      { label: 'ISP', value: geo?.isp ?? null },
      { label: 'ASN', value: geo?.asn ?? null },
      { label: 'Hosting / Organization', value: null },
      { label: 'Confidence', value: null },
      { label: 'Evidence Source', value: ioc.source },
    ];
  }
  if (ioc.type === 'Domain') {
    const parts = ioc.value.split('.');
    const tld = parts.length > 1 ? `.${parts[parts.length - 1]}` : null;
    return [
      { label: 'Domain', value: ioc.value },
      { label: 'TLD', value: tld },
      { label: 'Look-alike / Similarity Result', value: ioc.tags.includes('Lookalike') ? 'Flagged as look-alike domain' : null },
      { label: 'DNS Information', value: null },
      { label: 'MX Information', value: null },
      { label: 'Domain Intelligence', value: null },
      { label: 'Evidence Source', value: ioc.source },
    ];
  }
  if (ioc.type === 'URL') {
    let hostname: string | null = null;
    let https: string | null = null;
    const structure: string[] = [];
    try {
      const u = new URL(ioc.value);
      hostname = u.hostname;
      https = u.protocol === 'https:' ? 'Yes' : 'No';
      if (u.search) structure.push('Contains query parameters');
      const depth = u.pathname.split('/').filter(Boolean).length;
      if (depth > 0) structure.push(`Path depth: ${depth}`);
      if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) structure.push('Hostname is a raw IP literal');
    } catch {
      // Not a parseable absolute URL — leave derived fields unavailable.
    }
    const domainRelationship = hostname
      ? hostname.endsWith(email.senderDomain)
        ? 'Matches sender domain'
        : 'External to sender domain'
      : null;
    return [
      { label: 'Full URL', value: ioc.value },
      { label: 'Hostname', value: hostname },
      { label: 'HTTPS', value: https },
      { label: 'URL Structure Indicators', value: structure.length > 0 ? structure.join(' · ') : null },
      { label: 'Domain Relationship', value: domainRelationship },
      { label: 'Evidence Source', value: ioc.source },
    ];
  }
  // Hash / Email — the doc doesn't specify a dedicated schema for these, so
  // only the fields already present on the shared indicator record are shown.
  return [
    { label: 'Value', value: ioc.value },
    { label: 'Classification', value: statusLabel(ioc.reputation) },
    { label: 'Evidence Source', value: ioc.source },
    { label: 'First Seen', value: ioc.firstSeen },
    { label: 'Last Seen', value: ioc.lastSeen },
  ];
}

export function IndicatorsPage() {
  // Locally-owned selection — this page's own `indicatorsSelectedEmailId`.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [indicatorsSelectedEmailId, setIndicatorsSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );
  const [filter, setFilter] = useState<string>('ALL');
  const [query, setQuery] = useState('');
  const [drawerIoc, setDrawerIoc] = useState<ThreatIndicator | null>(null);

  const activeEmail = useMemo(() => getEmail(indicatorsSelectedEmailId), [getEmail, indicatorsSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
    setIndicatorsSelectedEmailId(email.id);
    setLastViewed(email.id);
    setDrawerIoc(null);
  };

  const indicators = activeEmail?.indicators ?? [];

  const filtered = useMemo(() => {
    return indicators.filter((ioc) => {
      const matchesType = filter === 'ALL' || ioc.type === filter;
      const matchesQuery =
        query === '' ||
        ioc.value.toLowerCase().includes(query.toLowerCase()) ||
        ioc.tags.some((t) => t.toLowerCase().includes(query.toLowerCase()));
      return matchesType && matchesQuery;
    });
  }, [indicators, filter, query]);

  const grouped = useMemo(() => {
    const map = new Map<IocType, ThreatIndicator[]>();
    for (const type of IOC_TYPES) {
      const items = filtered
        .filter((i) => i.type === type)
        .sort((a, b) => severityRank[a.reputation] - severityRank[b.reputation]);
      if (items.length > 0) map.set(type, items);
    }
    return map;
  }, [filtered]);

  const stats = useMemo(() => ({
    total: indicators.length,
    malicious: indicators.filter((i) => i.reputation === 'malicious').length,
    suspicious: indicators.filter((i) => i.reputation === 'suspicious').length,
    verified: indicators.filter((i) => i.reputation === 'clean').length,
    unavailable: indicators.filter((i) => i.reputation === 'unknown').length,
  }), [indicators]);

  const uniqueTypes = new Set(indicators.map((i) => i.type)).size;

  return (
    <InvestigationShell
      breadcrumb="Indicators"
      title="Indicators of Compromise"
      subtitle={activeEmail ? `${stats.total} indicators across ${uniqueTypes} types · ${activeEmail.id}` : undefined}
      hideCaseSelector={!activeEmail}
      selectedEmail={activeEmail}
      availableEmails={availableEmails}
      onSelectEmail={(id) => { setIndicatorsSelectedEmailId(id); setLastViewed(id); setDrawerIoc(null); }}
      onClearEmail={() => { setIndicatorsSelectedEmailId(null); setDrawerIoc(null); }}
      investigationNav={activeEmail ? { emailId: activeEmail.id, activeSection: 'indicators' } : undefined}
    >
      {!activeEmail ? (
        <InvestigationWorkspace onInvestigate={handleInvestigate} renderPreview={renderIndicatorsPreview} />
      ) : (
        <div key={activeEmail.id} className="animate-fade-in">
          <div className="grid grid-cols-5 gap-4 mb-6">
            <StatCard label="Total IOCs" value={stats.total} />
            <StatCard label="Malicious" value={stats.malicious} variant="danger" />
            <StatCard label="Suspicious" value={stats.suspicious} variant="warning" />
            <StatCard label="Verified" value={stats.verified} variant="success" />
            <StatCard label="Unavailable" value={stats.unavailable} />
          </div>

          <div className="flex items-center gap-3 mb-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-ink-600" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search indicators..."
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-base-800/60 border border-base-500/25 text-[12px] text-ink-200 placeholder:text-ink-700 focus:outline-none focus:border-accent-700/30 transition-colors"
              />
            </div>
            <div className="flex items-center gap-1.5">
              <Filter className="w-3 h-3 text-ink-600" />
              {typeFilters.map((t) => (
                <button
                  key={t}
                  onClick={() => setFilter(t)}
                  className={cn(
                    'px-2.5 py-1.5 rounded-md text-[10px] font-semibold uppercase tracking-wider transition-all',
                    filter === t
                      ? 'bg-accent-700/15 text-accent-400 border border-accent-700/25'
                      : 'text-ink-500 hover:text-ink-300 border border-transparent'
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Grouped by IOC type, per the doc's IPs / Domains / URLs / Hashes / Email Addresses layout */}
          {grouped.size > 0 ? (
            <div className="space-y-5">
              {IOC_TYPES.filter((t) => grouped.has(t)).map((type) => (
                <IocSection key={type} type={type} items={grouped.get(type)!} onOpen={setDrawerIoc} />
              ))}
            </div>
          ) : (
            <Card className="py-16 text-center">
              <Flag className="w-6 h-6 text-ink-700 mx-auto mb-3" />
              <p className="text-sm text-ink-600">No indicators match your search</p>
            </Card>
          )}

          {drawerIoc && (
            <IocDetailDrawer ioc={drawerIoc} email={activeEmail} onClose={() => setDrawerIoc(null)} />
          )}
        </div>
      )}
    </InvestigationShell>
  );
}

function IocSection({ type, items, onOpen }: { type: IocType; items: ThreatIndicator[]; onOpen: (ioc: ThreatIndicator) => void }) {
  const Icon = typeIcons[type];
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-base-500/20">
        <div className="flex items-center gap-2">
          <Icon className="w-3.5 h-3.5 text-accent-500" />
          <SectionLabel>{typeSectionLabel[type]}</SectionLabel>
        </div>
        <Badge variant="neutral">{items.length}</Badge>
      </div>
      <div className="divide-y divide-base-500/10">
        {items.map((ioc) => (
          <button
            key={ioc.id}
            onClick={() => onOpen(ioc)}
            className="w-full flex items-center gap-4 px-5 py-3 text-left hover:bg-base-700/30 transition-colors group"
          >
            <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', statusDot(ioc.reputation))} />
            <span className="mono text-[12px] text-ink-200 flex-1 min-w-0 truncate">{ioc.value}</span>
            <span className={cn('text-[10px] font-semibold uppercase tracking-wider shrink-0', statusColor(ioc.reputation))}>
              {statusLabel(ioc.reputation)}
            </span>
            <span className="text-[10px] text-ink-600 shrink-0 hidden md:inline">{ioc.source}</span>
            <div className="flex flex-wrap gap-1 shrink-0 max-w-[180px] justify-end">
              {ioc.tags.slice(0, 2).map((tag) => (
                <span key={tag} className="px-1.5 py-0.5 rounded text-[9px] font-medium bg-base-600/40 text-ink-500 border border-base-500/20 uppercase tracking-wider">
                  {tag}
                </span>
              ))}
            </div>
          </button>
        ))}
      </div>
    </Card>
  );
}

function IocDetailDrawer({ ioc, email, onClose }: { ioc: ThreatIndicator; email: ScannedEmail; onClose: () => void }) {
  const Icon = typeIcons[ioc.type] || Flag;
  const fields = getIocDetailFields(ioc, email);

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <div className="relative w-full max-w-md h-full bg-base-900 border-l border-base-500/30 shadow-2xl shadow-black/50 overflow-y-auto scrollbar-thin animate-slide-in-right">
        <div className="sticky top-0 flex items-center justify-between px-5 py-4 border-b border-base-500/20 bg-base-900/95 backdrop-blur-sm">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-accent-700/10 border border-accent-700/25 shrink-0">
              <Icon className="w-4 h-4 text-accent-400" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-500">{ioc.type} Detail</div>
              <div className="mono text-[12px] text-ink-100 truncate">{ioc.value}</div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="flex items-center justify-center w-8 h-8 rounded-lg text-ink-500 hover:text-ink-200 hover:bg-base-700/60 transition-colors shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-5">
          <div className="flex items-center gap-2 mb-5">
            <span className={cn('w-2 h-2 rounded-full', statusDot(ioc.reputation))} />
            <span className={cn('text-[12px] font-bold uppercase tracking-wider', statusColor(ioc.reputation))}>
              {statusLabel(ioc.reputation)}
            </span>
          </div>

          <div className="space-y-3">
            {fields.map((f) => (
              <DetailFieldRow key={f.label} field={f} />
            ))}
          </div>

          <Divider className="my-5" />

          <SectionLabel className="block mb-2.5">Timeline</SectionLabel>
          <div className="grid grid-cols-2 gap-3 mb-5">
            <PreviewField label="First Seen" value={ioc.firstSeen} mono />
            <PreviewField label="Last Seen" value={ioc.lastSeen} mono />
          </div>

          {ioc.tags.length > 0 && (
            <>
              <SectionLabel className="block mb-2.5">Tags</SectionLabel>
              <div className="flex flex-wrap gap-1.5">
                {ioc.tags.map((tag) => (
                  <Badge key={tag} variant="warning">{tag}</Badge>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function DetailFieldRow({ field }: { field: DetailField }) {
  const isUnavailable = field.value === null || field.value === '';
  return (
    <div className="panel-2 p-3">
      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-1">{field.label}</div>
      {isUnavailable ? (
        <div className="flex items-center gap-1.5 text-[11px] text-ink-600 italic">
          <ShieldQuestion className="w-3 h-3 shrink-0" /> UNAVAILABLE
        </div>
      ) : (
        <div className="mono text-[12px] text-ink-200 break-all">{field.value}</div>
      )}
    </div>
  );
}

function StatCard({ label, value, variant }: { label: string; value: number; variant?: 'danger' | 'warning' | 'success' }) {
  const colorClass = variant === 'danger' ? 'text-accent-500' : variant === 'warning' ? 'text-amber-400' : variant === 'success' ? 'text-emerald-400' : 'text-ink-100';
  return (
    <Card className="p-4">
      <div className={cn('text-3xl font-bold tabular-nums', colorClass)}>{value}</div>
      <div className="section-label mt-1">{label}</div>
    </Card>
  );
}

/**
 * Indicators-only single-click preview — type counts (IP/Domain/URL/Hash/
 * Email) plus the highest-severity example per type, per the doc. Reputation
 * is shown using the doc's actual status vocabulary; nothing is fabricated —
 * an indicator with no intel is labeled Unavailable, not guessed at.
 */
function renderIndicatorsPreview(email: ScannedEmail, onInvestigate: () => void) {
  const iocs = email.indicators;
  const counts = IOC_TYPES.map((type) => ({ type, count: iocs.filter((i) => i.type === type).length }));
  const topByType = IOC_TYPES.map((type) => {
    const items = iocs.filter((i) => i.type === type).sort((a, b) => severityRank[a.reputation] - severityRank[b.reputation]);
    return items[0] ?? null;
  }).filter((i): i is ThreatIndicator => i !== null);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Indicators Preview</SectionLabel>
        <Badge variant="neutral">{iocs.length} total</Badge>
      </div>

      <div className="min-w-0 mb-4">
        <div className="text-[13px] font-semibold text-ink-100 leading-snug truncate">{email.subject}</div>
        <div className="mono text-[10px] text-ink-500 mt-1">{email.caseId || email.id}</div>
      </div>

      <SectionLabel className="block mb-2.5">Indicator Counts</SectionLabel>
      <div className="grid grid-cols-5 gap-1.5 mb-4">
        {counts.map(({ type, count }) => (
          <div key={type} className="panel-2 p-2 text-center">
            <div className="text-[13px] font-bold text-ink-200 tabular-nums leading-none">{count}</div>
            <div className="text-[8px] text-ink-600 uppercase tracking-wider mt-1">{type}</div>
          </div>
        ))}
      </div>

      <SectionLabel className="block mb-2.5">Most Important Indicators</SectionLabel>
      {topByType.length > 0 ? (
        <div className="space-y-1.5 mb-5">
          {topByType.map((ioc) => (
            <div key={ioc.id} className="text-[11px] panel-2 px-2.5 py-2">
              <div className="flex items-center gap-2">
                <span className="mono text-ink-600 shrink-0 w-11 uppercase text-[9px]">{ioc.type}:</span>
                <span className="text-ink-300 truncate mono flex-1">{ioc.value}</span>
              </div>
              <div className="flex items-center gap-1.5 mt-1 pl-[52px]">
                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', statusDot(ioc.reputation))} />
                <span className={cn('text-[9px] font-semibold uppercase tracking-wider', statusColor(ioc.reputation))}>
                  {statusLabel(ioc.reputation)}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-[11px] text-ink-600 mb-5">No indicators for this email</div>
      )}

      <PreviewInvestigateButton label="View All Indicators" onClick={onInvestigate} />
    </div>
  );
}
