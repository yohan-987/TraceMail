import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

interface CardProps {
  children: ReactNode;
  className?: string;
  variant?: 'default' | 'elevated';
}

export function Card({ children, className, variant = 'default' }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-xl border',
        variant === 'default' ? 'bg-base-800/80 border-base-500/40' : 'bg-base-700/70 border-base-500/50',
        className
      )}
    >
      {children}
    </div>
  );
}

interface SectionLabelProps {
  children: ReactNode;
  className?: string;
}

export function SectionLabel({ children, className }: SectionLabelProps) {
  return (
    <span className={cn('text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-500', className)}>
      {children}
    </span>
  );
}

type BadgeVariant = 'neutral' | 'danger' | 'warning' | 'success' | 'active' | 'critical';

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
}

const badgeStyles: Record<BadgeVariant, string> = {
  neutral: 'bg-base-600/60 text-ink-300 border-base-400/40',
  danger: 'bg-accent-900/20 text-accent-400 border-accent-700/30',
  warning: 'bg-amber-900/15 text-amber-400 border-amber-700/20',
  success: 'bg-emerald-900/15 text-emerald-400 border-emerald-700/20',
  active: 'bg-accent-700/20 text-accent-400 border-accent-600/40 accent-glow-sm',
  critical: 'bg-accent-700/30 text-accent-300 border-accent-600/50 threat-glow',
};

export function Badge({ children, variant = 'neutral', className }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md border text-[10px] font-semibold uppercase tracking-wider',
        badgeStyles[variant],
        className
      )}
    >
      {children}
    </span>
  );
}

interface MetricProps {
  value: ReactNode;
  label: string;
  className?: string;
}

export function Metric({ value, label, className }: MetricProps) {
  return (
    <div className={className}>
      <div className="text-2xl font-bold text-ink-100 tabular-nums">{value}</div>
      <div className="section-label mt-1">{label}</div>
    </div>
  );
}

interface StatusDotProps {
  status: 'online' | 'warning' | 'critical' | 'idle';
  className?: string;
}

const dotStyles: Record<StatusDotProps['status'], string> = {
  online: 'bg-emerald-500',
  warning: 'bg-amber-500',
  critical: 'bg-accent-600',
  idle: 'bg-ink-600',
};

export function StatusDot({ status, className }: StatusDotProps) {
  return (
    <span className={cn('relative flex h-2 w-2', className)}>
      {(status === 'online' || status === 'critical') && (
        <span
          className={cn(
            'absolute inline-flex h-full w-full rounded-full opacity-60 animate-ping',
            dotStyles[status]
          )}
        />
      )}
      <span className={cn('relative inline-flex rounded-full h-2 w-2', dotStyles[status])} />
    </span>
  );
}

interface DividerProps {
  className?: string;
}

export function Divider({ className }: DividerProps) {
  return <div className={cn('h-px bg-gradient-to-r from-transparent via-base-400/30 to-transparent', className)} />;
}
