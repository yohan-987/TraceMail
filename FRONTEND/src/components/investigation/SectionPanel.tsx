import { useId, useState, type ReactNode } from 'react';
import { ChevronDown, Info } from 'lucide-react';
import { Card } from '@/components/ui/Primitives';
import { cn } from '@/lib/utils';

/**
 * Prompt 12 — one consistent, per-section "What does this mean?" control.
 *
 * Built on a native <button> with aria-expanded / aria-controls, so
 * Enter/Space activation and focus behaviour come from the platform.
 * Each section owns its own open/closed state; there is deliberately no
 * global explanation area.
 */

export function useExplain(defaultOpen = false) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();
  return { open, panelId, toggle: () => setOpen((v) => !v) };
}

export function ExplainToggle({
  open,
  panelId,
  onToggle,
  className,
}: {
  open: boolean;
  panelId: string;
  onToggle: () => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-controls={panelId}
      onClick={onToggle}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border border-base-500/40 bg-base-900/40 px-2.5 py-1.5',
        'text-[11px] font-medium text-ink-300 transition-colors whitespace-nowrap',
        'hover:text-ink-100 hover:border-sky-500/40',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/60',
        open && 'border-sky-500/40 text-ink-100',
        className
      )}
    >
      What does this mean?
      <ChevronDown
        aria-hidden="true"
        className={cn('w-3.5 h-3.5 transition-transform duration-150', open && 'rotate-180')}
      />
    </button>
  );
}

export function ExplainPanel({
  open,
  panelId,
  paragraphs,
  className,
}: {
  open: boolean;
  panelId: string;
  paragraphs: string[];
  className?: string;
}) {
  return (
    <div
      id={panelId}
      role="region"
      aria-label="Plain-English explanation"
      hidden={!open}
      className={cn('rounded-lg border border-sky-500/20 bg-sky-500/[0.05] p-3.5', className)}
    >
      <div className="flex items-center gap-1.5 text-[12px] font-semibold text-sky-500 mb-1.5">
        <Info aria-hidden="true" className="w-3.5 h-3.5" />
        What does this mean?
      </div>
      <div className="space-y-2">
        {paragraphs.map((text, i) => (
          <p key={i} className="text-[12px] leading-relaxed text-ink-300">
            {text}
          </p>
        ))}
      </div>
    </div>
  );
}

interface SectionPanelProps {
  icon?: ReactNode;
  title: string;
  /** Provenance tag / badge shown next to the title. */
  tag?: ReactNode;
  /** Extra header content shown just before the explanation toggle (e.g. a status pill). */
  headerExtra?: ReactNode;
  explanation: string[];
  /** On very wide screens (2xl and up), open the explanation to the right of the content, as in the
   *  reference design, instead of above it. Below 2xl it always stacks above the content, so the
   *  content never gets squeezed into a narrow column. */
  explainSide?: boolean;
  defaultExplainOpen?: boolean;
  className?: string;
  children: ReactNode;
}

export function SectionPanel({
  icon,
  title,
  tag,
  headerExtra,
  explanation,
  explainSide,
  defaultExplainOpen = false,
  className,
  children,
}: SectionPanelProps) {
  const { open, panelId, toggle } = useExplain(defaultExplainOpen);
  const titleId = useId();
  const sideOpen = open && !!explainSide;

  return (
    <section aria-labelledby={titleId} className={cn('min-w-0', className)}>
      <Card className="p-4 h-full">
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 mb-3">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 min-w-0">
            {icon}
            <h2 id={titleId} className="text-[15px] font-semibold leading-tight text-ink-100">
              {title}
            </h2>
            {tag}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {headerExtra}
            <ExplainToggle open={open} panelId={panelId} onToggle={toggle} />
          </div>
        </div>

        <div
          className={cn(
            sideOpen ? 'grid gap-3 2xl:grid-cols-[minmax(0,1fr)_minmax(0,22rem)] 2xl:items-start' : 'space-y-3'
          )}
        >
          <ExplainPanel
            open={open}
            panelId={panelId}
            paragraphs={explanation}
            className={cn(sideOpen && '2xl:col-start-2 2xl:row-start-1')}
          />
          <div className={cn('min-w-0', sideOpen && '2xl:col-start-1 2xl:row-start-1')}>{children}</div>
        </div>
      </Card>
    </section>
  );
}

/** Compact "nothing to show" state — one line of status plus one line of
 *  explanation, never a large empty card. */
export function StatusNotice({
  label,
  status,
  message,
  statusClassName,
}: {
  label: string;
  status: string;
  message: string;
  statusClassName?: string;
}) {
  return (
    <div className="panel-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 px-3.5 py-2.5">
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-ink-400">
        {label}
        <span
          className={cn(
            'rounded border px-2 py-0.5 text-[10px] font-bold tracking-wider',
            statusClassName ?? 'border-amber-700/30 bg-amber-900/15 text-amber-400'
          )}
        >
          {status}
        </span>
      </div>
      <p className="flex items-start gap-1.5 text-[12px] text-ink-400 leading-relaxed min-w-0">
        <Info aria-hidden="true" className="w-3.5 h-3.5 mt-0.5 shrink-0 text-sky-500" />
        <span>{message}</span>
      </p>
    </div>
  );
}
