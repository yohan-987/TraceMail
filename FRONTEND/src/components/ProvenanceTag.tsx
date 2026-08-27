import { Eye, Binary, Radar, Cpu, Sparkles, Link2 } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * Six-value provenance taxonomy shared across every page that needs to
 * distinguish how a finding was produced. Used sparingly — one badge per
 * section/finding, never per field — so it never becomes visually
 * overwhelming.
 */
export type Provenance = 'observed' | 'deterministic' | 'external' | 'ml' | 'ai' | 'inferred';

export const provenanceMeta: Record<Provenance, { label: string; icon: typeof Eye; color: string; description: string }> = {
  observed: {
    label: 'Observed',
    icon: Eye,
    color: 'text-ink-400 border-ink-600/30 bg-ink-800/30',
    description: 'Directly present in raw email headers/content',
  },
  deterministic: {
    label: 'Deterministic Analysis',
    icon: Binary,
    color: 'text-sky-400 border-sky-700/30 bg-sky-900/10',
    description: 'Rule-based / algorithmic evaluation of observed data',
  },
  external: {
    label: 'External Intelligence',
    icon: Radar,
    color: 'text-cyan-400 border-cyan-700/30 bg-cyan-900/10',
    description: 'From external threat-intel or GeoIP lookups',
  },
  ml: {
    label: 'ML Assessment',
    icon: Cpu,
    color: 'text-violet-400 border-violet-700/30 bg-violet-900/10',
    description: 'Machine-learning model output',
  },
  ai: {
    label: 'AI Interpretation',
    icon: Sparkles,
    color: 'text-amber-400 border-amber-700/30 bg-amber-900/10',
    description: 'AI-generated narrative interpretation, based on the evidence above it — never the source of raw technical facts',
  },
  inferred: {
    label: 'Inferred',
    icon: Link2,
    color: 'text-ink-400 border-ink-600/30 bg-ink-800/30',
    description: 'Pattern-based conclusion, not directly observed',
  },
};

export function ProvenanceTag({ type, className }: { type: Provenance; className?: string }) {
  const meta = provenanceMeta[type];
  const Icon = meta.icon;
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-[8px] font-semibold uppercase tracking-wider border', meta.color, className)}>
      <Icon className="w-2.5 h-2.5" /> {meta.label}
    </span>
  );
}
