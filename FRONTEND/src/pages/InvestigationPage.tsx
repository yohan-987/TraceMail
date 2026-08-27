import { useState, useMemo } from 'react';
import {
  AlertTriangle,
  Flag,
  Network,
  ShieldX,
  ChevronRight,
  ArrowLeft,
} from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { ThreatRing } from '@/components/ThreatRing';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { useActiveCase } from '@/context/ActiveCaseContext';
import { CaseSelector } from '@/components/CaseSelector';
import { InvestigationWorkspace } from '@/components/InvestigationWorkspace';
import { InvestigationNavigation } from '@/components/InvestigationNavigation';
import type { ScannedEmail } from '@/data/mockData';
import { cn } from '@/lib/utils';

export function InvestigationPage() {
  // Locally-owned selection — this page's own `investigationSelectedEmailId`.
  const location = useLocation();
  const { getEmail, setLastViewed, availableEmails } = useActiveCase();
  const [investigationSelectedEmailId, setInvestigationSelectedEmailId] = useState<string | null>(
    (location.state as { emailId?: string } | null)?.emailId ?? null
  );

  const activeEmail = useMemo(() => getEmail(investigationSelectedEmailId), [getEmail, investigationSelectedEmailId]);

  const handleInvestigate = (email: ScannedEmail) => {
    setInvestigationSelectedEmailId(email.id);
    setLastViewed(email.id);
  };

  if (!activeEmail) {
    return (
      <div className="px-8 py-6 max-w-[1600px] mx-auto">
        <div className="flex items-center gap-2 mb-4">
          <Link to="/" className="flex items-center gap-1 text-[11px] font-medium text-ink-500 hover:text-accent-400 transition-colors uppercase tracking-wider">
            <ArrowLeft className="w-3 h-3" /> Triage
          </Link>
          <span className="text-ink-700 text-xs">/</span>
          <span className="text-[11px] font-medium text-ink-400 uppercase tracking-wider">Investigation</span>
        </div>
        <InvestigationWorkspace onInvestigate={handleInvestigate} />
      </div>
    );
  }

  const isThreat = activeEmail.threatScore >= 60;
  const maliciousIocCount = activeEmail.indicators.filter((i) => i.reputation === 'malicious').length;
  const suspiciousIocCount = activeEmail.indicators.filter((i) => i.reputation === 'suspicious').length;

  return (
    <div className="flex flex-col min-h-full">
      <div className="px-8 py-6 pb-28 max-w-[1600px] mx-auto w-full">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 mb-4">
        <Link to="/" className="flex items-center gap-1 text-[11px] font-medium text-ink-500 hover:text-accent-400 transition-colors uppercase tracking-wider">
          <ArrowLeft className="w-3 h-3" /> Triage
        </Link>
        <span className="text-ink-700 text-xs">/</span>
        <span className="text-[11px] font-medium text-ink-400 uppercase tracking-wider">Investigation</span>
        <ChevronRight className="w-3 h-3 text-ink-700" />
        <span className="mono text-[11px] text-ink-300">{activeEmail.caseId || activeEmail.id}</span>
      </div>

      {/* Case selector — always visible */}
      <CaseSelector
        className="mb-5"
        selected={activeEmail}
        availableEmails={availableEmails}
        onSelect={(id) => { setInvestigationSelectedEmailId(id); setLastViewed(id); }}
        onClear={() => setInvestigationSelectedEmailId(null)}
      />

      {/* Page heading */}
      <div className="flex items-end justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-ink-50">{activeEmail.subject}</h1>
          <p className="text-xs text-ink-500 mt-1 mono">{activeEmail.id} · {activeEmail.sender} · {activeEmail.date}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={isThreat ? 'critical' : 'neutral'}>{activeEmail.riskLevel}</Badge>
          <Badge variant={isThreat ? 'danger' : 'neutral'}>{activeEmail.classification}</Badge>
        </div>
      </div>

      {/* Main grid: threat ring + threat summary + why flagged */}
      <div className="grid grid-cols-12 gap-5">
        <Card className="col-span-4 flex flex-col items-center justify-center py-10 min-h-[420px] relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 flex justify-center pt-4">
            <SectionLabel>Threat Assessment</SectionLabel>
          </div>
          <ThreatRing
            mode="result"
            score={activeEmail.threatScore}
            riskLevel={activeEmail.riskLevel}
            threatType={activeEmail.classification}
            size={300}
          />
        </Card>

        <div className="col-span-8 space-y-5">
          <Card className="p-5">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-accent-500" />
                <SectionLabel>Threat Summary</SectionLabel>
              </div>
              <Badge variant={isThreat ? 'critical' : 'neutral'}>
                {isThreat ? 'VERDICT: MALICIOUS' : 'VERDICT: SAFE'}
              </Badge>
            </div>
            <p className="text-sm text-ink-300 leading-relaxed">{activeEmail.threatSummary}</p>
          </Card>

          {activeEmail.whyFlagged.length > 0 && (
            <Card className="p-5">
              <div className="flex items-center gap-2 mb-3">
                <Flag className="w-3.5 h-3.5 text-accent-500" />
                <SectionLabel>Why Flagged</SectionLabel>
              </div>
              <ul className="space-y-2.5">
                {activeEmail.whyFlagged.map((reason, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-[13px] text-ink-300 leading-relaxed">
                    <span className="mono text-[10px] text-accent-600 mt-0.5 shrink-0">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      </div>

      {/* Quick stats row */}
      <div className="grid grid-cols-12 gap-5 mt-5">
        <Card className="col-span-4 p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldX className="w-3.5 h-3.5 text-accent-500" />
            <SectionLabel>Authentication Status</SectionLabel>
          </div>
          <div className="space-y-3">
            <AuthRow label="SPF" status={activeEmail.spf} />
            <AuthRow label="DKIM" status={activeEmail.dkim} />
            <AuthRow label="DMARC" status={activeEmail.dmarc} />
          </div>
          <Divider className="my-4" />
          <p className="text-[11px] text-ink-500 leading-relaxed">{activeEmail.authenticationSummary}</p>
        </Card>

        <Card className="col-span-4 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Flag className="w-3.5 h-3.5 text-accent-500" />
              <SectionLabel>IOC Summary</SectionLabel>
            </div>
            <Link to="/indicators" state={{ emailId: activeEmail.id }} className="flex items-center gap-1 text-[10px] font-medium text-ink-500 hover:text-accent-400 transition-colors uppercase tracking-wider">
              View All <ChevronRight className="w-2.5 h-2.5" />
            </Link>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="panel-2 p-3">
              <div className="text-2xl font-bold text-accent-500 tabular-nums">{maliciousIocCount}</div>
              <div className="section-label mt-1">Malicious</div>
            </div>
            <div className="panel-2 p-3">
              <div className="text-2xl font-bold text-amber-400 tabular-nums">{suspiciousIocCount}</div>
              <div className="section-label mt-1">Suspicious</div>
            </div>
          </div>
          <div className="space-y-1.5">
            {activeEmail.indicators.slice(0, 4).map((ioc) => (
              <div key={ioc.id} className="flex items-center gap-2 text-[11px]">
                <span className="mono text-ink-600 shrink-0 w-10">{ioc.type}</span>
                <span className="text-ink-400 truncate">{ioc.value}</span>
                <span
                  className={cn(
                    'ml-auto shrink-0 w-1.5 h-1.5 rounded-full',
                    ioc.reputation === 'malicious' ? 'bg-accent-600' : ioc.reputation === 'suspicious' ? 'bg-amber-500' : 'bg-ink-600'
                  )}
                />
              </div>
            ))}
          </div>
        </Card>

        <Card className="col-span-4 p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Network className="w-3.5 h-3.5 text-accent-500" />
              <SectionLabel>Infrastructure Summary</SectionLabel>
            </div>
            <Link to="/infrastructure" state={{ emailId: activeEmail.id }} className="flex items-center gap-1 text-[10px] font-medium text-ink-500 hover:text-accent-400 transition-colors uppercase tracking-wider">
              View All <ChevronRight className="w-2.5 h-2.5" />
            </Link>
          </div>
          <div className="space-y-2.5">
            {activeEmail.geoData.length > 0 ? (
              activeEmail.geoData.map((geo) => (
                <div key={geo.ip} className="panel-2 p-3 flex items-center gap-3">
                  <div className="flex items-center justify-center w-8 h-8 rounded-md bg-base-600/50 border border-base-500/30">
                    <span className="text-[10px] font-bold text-ink-400 mono">{geo.flag}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="mono text-[11px] text-ink-300 truncate">{geo.ip}</div>
                    <div className="text-[10px] text-ink-600">{geo.city}, {geo.country}</div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-ink-500">{geo.isp}</div>
                    <div className="text-[9px] text-ink-700 mono">{geo.asn}</div>
                  </div>
                </div>
              ))
            ) : (
              <div className="text-[11px] text-ink-600 text-center py-8">No infrastructure data</div>
            )}
          </div>
        </Card>
      </div>
      </div>

      {/* Shared persistent investigation navigation — same component every
          full-investigation page uses, no duplicated markup. */}
      <InvestigationNavigation emailId={activeEmail.id} activeSection="overview" />
    </div>
  );
}

function AuthRow({ label, status }: { label: string; status: string }) {
  const isFail = status === 'fail' || status === 'none';
  return (
    <div className="flex items-center justify-between py-1.5 px-3 rounded-lg bg-base-700/40 border border-base-500/20">
      <span className="text-[12px] font-semibold text-ink-300 uppercase tracking-wider">{label}</span>
      <div className="flex items-center gap-2">
        <span
          className={cn(
            'mono text-[11px] font-medium uppercase',
            isFail ? 'text-accent-400' : 'text-emerald-400'
          )}
        >
          {status}
        </span>
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            isFail ? 'bg-accent-600 accent-glow-sm' : 'bg-emerald-500'
          )}
        />
      </div>
    </div>
  );
}
