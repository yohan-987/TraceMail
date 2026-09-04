import { useState, useMemo, type ReactNode } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CircleHelp,
  ArrowRight,
  Mouse,
  Server,
  Globe,
  Link2,
  Paperclip,
  Flag,
} from 'lucide-react';
import { Card, SectionLabel, Badge, Divider } from '@/components/ui/Primitives';
import { EmailTable } from '@/components/EmailTable';
import { useActiveCase } from '@/context/ActiveCaseContext';
import type { EmailStatus, ScannedEmail } from '@/types/email';
import { cn } from '@/lib/utils';

export const statusIcon: Record<EmailStatus, typeof ShieldCheck> = {
  safe: ShieldCheck,
  suspicious: ShieldAlert,
  malicious: ShieldX,
  inconclusive: CircleHelp,
};

export const statusColor: Record<EmailStatus, string> = {
  safe: 'text-emerald-400',
  suspicious: 'text-amber-400',
  malicious: 'text-accent-400',
  inconclusive: 'text-ink-400',
};

interface InvestigationWorkspaceProps {
  onInvestigate: (email: ScannedEmail) => void;
  /**
   * Optional tab-specific preview renderer. If omitted, the generic
   * quick-triage summary (sender/subject/score/auth/IOCs/why-flagged) is
   * used — that's the right default for the Investigation hub, since it IS
   * the email overview. Forensics/Indicators/Infrastructure/AI/Reports each
   * pass their own renderer so the single-click preview only shows what's
   * relevant to that tab, not the generic overview.
   */
  renderPreview?: (email: ScannedEmail, onInvestigate: () => void) => ReactNode;
  /** Opt-in only — adds a Case ID filter to the underlying table. Reports
   *  uses this; Forensics/Indicators/Infrastructure don't and are unaffected. */
  enableCaseFilter?: boolean;
}

/**
 * Shared two-panel investigation workspace.
 * Left: the full, searchable/sortable/paginated email table.
 * Right: a fast triage preview of whichever email was last single-clicked.
 *
 * Single click  -> updates the local preview AND live-updates the shared
 * "last viewed" pointer (Header banner + ★ pinned row everywhere), so
 * browsing always reflects immediately with no refresh needed.
 * Double click / "Investigate" -> calls onInvestigate, which the owning page
 * uses to promote the email into ITS OWN local selection state (full detail).
 */
export function InvestigationWorkspace({ onInvestigate, renderPreview, enableCaseFilter }: InvestigationWorkspaceProps) {
  const { getEmail, setLastViewed } = useActiveCase();
  const [previewId, setPreviewId] = useState<string | null>(null);

  const previewEmail = useMemo(() => getEmail(previewId), [getEmail, previewId]);

  const handleSelect = (email: ScannedEmail) => {
    setPreviewId(email.id);
    setLastViewed(email.id);
  };

  return (
    <div className="grid grid-cols-12 gap-5">
      <Card className="col-span-7 overflow-hidden h-[620px]">
        <EmailTable
          selectedId={previewId}
          onSelect={handleSelect}
          onInvestigate={onInvestigate}
          enableCaseFilter={enableCaseFilter}
        />
      </Card>

      <Card className="col-span-5 h-[620px] overflow-y-auto scrollbar-thin p-5">
        {previewEmail ? (
          <div key={previewEmail.id} className="h-full animate-fade-in">
            {renderPreview ? (
              renderPreview(previewEmail, () => onInvestigate(previewEmail))
            ) : (
              <EmailPreview email={previewEmail} onInvestigate={() => onInvestigate(previewEmail)} />
            )}
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center px-4">
            <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-base-800 border border-base-500/30 mb-4">
              <Mouse className="w-5 h-5 text-ink-600" />
            </div>
            <h3 className="text-sm font-semibold text-ink-300">No Email Selected</h3>
            <p className="text-[11px] text-ink-600 mt-1.5 max-w-[240px] leading-relaxed">
              Click any email on the left for a quick risk preview. Double-click, or use Investigate, to open the full workspace.
            </p>
          </div>
        )}
      </Card>
    </div>
  );
}

export function EmailPreview({
  email,
  onInvestigate,
  investigateLabel = 'Investigate',
  onReport,
}: {
  email: ScannedEmail;
  onInvestigate: () => void;
  investigateLabel?: string;
  onReport?: () => void;
}) {
  const Icon = statusIcon[email.status];
  // Defensive: a lightweight/partial record (e.g. from an API list response
  // or a page still loading full details) may not carry these deep arrays —
  // never assume they're present.
  const indicators = email.indicators ?? [];
  const whyFlagged = email.whyFlagged ?? [];
  const ips = indicators.filter((i) => i.type === 'IP').length;
  const domains = indicators.filter((i) => i.type === 'Domain').length;
  const urls = indicators.filter((i) => i.type === 'URL').length;
  const isThreat = email.threatScore >= 60;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <SectionLabel>Selected Email</SectionLabel>
        <Badge variant={isThreat ? 'danger' : 'neutral'}>{email.classification}</Badge>
      </div>

      <div className="flex items-start gap-3 mb-4">
        <Icon className={cn('w-5 h-5 mt-0.5 shrink-0', statusColor[email.status])} />
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-ink-100 leading-snug">{email.subject}</div>
          <div className="mono text-[10px] text-ink-500 mt-1">{email.caseId || email.id}</div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2.5 mb-4">
        <PreviewField label="Sender" value={email.sender} mono />
        <PreviewField label="Recipient" value={email.recipient} mono />
        <PreviewField label="Date" value={email.date} mono />
        <PreviewField
          label="Threat Score"
          value={String(email.threatScore)}
          valueClassName={isThreat ? 'text-accent-400' : 'text-emerald-400'}
        />
      </div>

      <Divider className="mb-4" />

      <SectionLabel className="block mb-2.5">Authentication</SectionLabel>
      <div className="flex items-center gap-2 mb-4">
        <AuthChip label="SPF" status={email.spf} />
        <AuthChip label="DKIM" status={email.dkim} />
        <AuthChip label="DMARC" status={email.dmarc} />
      </div>

      <SectionLabel className="block mb-2.5">Key Indicators</SectionLabel>
      <div className="grid grid-cols-2 gap-2 mb-4">
        <IocChip icon={Server} label="IPs" count={ips} />
        <IocChip icon={Globe} label="Domains" count={domains} />
        <IocChip icon={Link2} label="URLs" count={urls} />
        <IocChip icon={Paperclip} label="Attachments" count={0} />
      </div>

      {whyFlagged.length > 0 && (
        <>
          <div className="flex items-center gap-2 mb-2.5">
            <Flag className="w-3 h-3 text-accent-500" />
            <SectionLabel>Why Flagged</SectionLabel>
          </div>
          <ul className="space-y-2 mb-5">
            {whyFlagged.slice(0, 5).map((reason, i) => (
              <li key={i} className="flex items-start gap-2 text-[11px] text-ink-400 leading-relaxed">
                <span className="mono text-[9px] text-accent-600 mt-0.5 shrink-0">
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </>
      )}

      <div className="mt-auto flex items-center gap-2">
        {onReport && (
          <button
            onClick={onReport}
            className="flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-lg text-[11px] font-bold uppercase tracking-wider text-ink-400 bg-base-700/50 border border-base-500/30 hover:bg-base-700/80 transition-colors"
          >
            Report
          </button>
        )}
        <button
          onClick={onInvestigate}
          className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[11px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors"
        >
          {investigateLabel} <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}

function PreviewField({
  label,
  value,
  mono,
  valueClassName,
}: {
  label: string;
  value: string;
  mono?: boolean;
  valueClassName?: string;
}) {
  return (
    <div className="panel-2 p-2.5">
      <div className="text-[9px] font-semibold uppercase tracking-wider text-ink-500 mb-0.5">{label}</div>
      <div className={cn('text-[12px] truncate', mono && 'mono', valueClassName ?? 'text-ink-200')}>{value}</div>
    </div>
  );
}

export function AuthChip({ label, status }: { label: string; status: string }) {
  const isFail = status !== 'pass';
  return (
    <div
      className={cn(
        'flex-1 flex flex-col items-center gap-0.5 py-2 rounded-lg border',
        isFail ? 'border-accent-700/25 bg-accent-700/5' : 'border-emerald-700/20 bg-emerald-700/5'
      )}
    >
      <span className="text-[9px] font-semibold uppercase tracking-wider text-ink-500">{label}</span>
      <span className={cn('mono text-[10px] font-bold uppercase', isFail ? 'text-accent-400' : 'text-emerald-400')}>
        {status}
      </span>
    </div>
  );
}

export function IocChip({ icon: Icon, label, count }: { icon: typeof Server; label: string; count: number }) {
  return (
    <div className="panel-2 p-2.5 flex items-center gap-2">
      <Icon className="w-3.5 h-3.5 text-ink-500 shrink-0" />
      <div className="min-w-0">
        <div className="text-[13px] font-bold text-ink-200 tabular-nums leading-none">{count}</div>
        <div className="text-[9px] text-ink-600 uppercase tracking-wider mt-0.5">{label}</div>
      </div>
    </div>
  );
}

/** Shared "Investigate" CTA button used at the bottom of every tab-specific preview. */
export function PreviewInvestigateButton({ label = 'Investigate', onClick }: { label?: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="mt-auto flex items-center justify-center gap-2 w-full py-2.5 rounded-lg text-[11px] font-bold uppercase tracking-wider text-accent-400 bg-accent-700/10 border border-accent-700/30 hover:bg-accent-700/20 transition-colors"
    >
      {label} <ArrowRight className="w-3.5 h-3.5" />
    </button>
  );
}

export { PreviewField };