import { useEffect, useState } from 'react';
import { cn } from '@/lib/utils';

type ThreatRingMode = 'scanning' | 'result';

interface ScanSection {
  key: string;
  label: string;
}

const SCAN_SECTIONS: ScanSection[] = [
  { key: 'header', label: 'HEADER' },
  { key: 'auth', label: 'AUTH' },
  { key: 'content', label: 'CONTENT' },
  { key: 'url', label: 'URL' },
  { key: 'domain', label: 'DOMAIN' },
  { key: 'ipgeo', label: 'IP / GEO' },
];

interface ThreatRingProps {
  mode: ThreatRingMode;
  /** Scanning mode: 0–100 progress */
  progress?: number;
  /** Result mode: 0–100 threat score */
  score?: number;
  /** Result mode: risk level label */
  riskLevel?: string;
  /** Result mode: threat type */
  threatType?: string;
  /** Diameter in pixels */
  size?: number;
  className?: string;
}

export function ThreatRing({
  mode,
  progress = 0,
  score = 0,
  riskLevel = 'HIGH RISK',
  threatType = 'PHISHING',
  size = 340,
  className,
}: ThreatRingProps) {
  const [displayProgress, setDisplayProgress] = useState(0);
  const [displayScore, setDisplayScore] = useState(0);
  const [activeSection, setActiveSection] = useState(0);

  useEffect(() => {
    if (mode === 'scanning') {
      const target = Math.min(progress, 100);
      const diff = target - displayProgress;
      if (Math.abs(diff) < 0.3) {
        setDisplayProgress(target);
      } else {
        const timer = setTimeout(() => setDisplayProgress(displayProgress + diff * 0.12), 30);
        return () => clearTimeout(timer);
      }
    }
  }, [mode, progress, displayProgress]);

  useEffect(() => {
    if (mode === 'result') {
      const target = Math.min(score, 100);
      const diff = target - displayScore;
      if (Math.abs(diff) < 0.5) {
        setDisplayScore(target);
      } else {
        const timer = setTimeout(() => setDisplayScore(displayScore + diff * 0.08), 25);
        return () => clearTimeout(timer);
      }
    }
  }, [mode, score, displayScore]);

  useEffect(() => {
    if (mode === 'scanning') {
      const idx = Math.min(
        Math.floor((displayProgress / 100) * SCAN_SECTIONS.length),
        SCAN_SECTIONS.length - 1
      );
      setActiveSection(idx);
    }
  }, [displayProgress, mode]);

  const strokeWidth = 3;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const dashValue =
    mode === 'scanning'
      ? (displayProgress / 100) * circumference
      : (displayScore / 100) * circumference;

  const isThreat = mode === 'result' && displayScore >= 60;

  return (
    <div
      className={cn('relative flex items-center justify-center', className)}
      style={{ width: size, height: size }}
    >
      {/* Outer glow */}
      <div
        className={cn(
          'absolute inset-0 rounded-full blur-2xl transition-opacity duration-700',
          mode === 'scanning'
            ? 'bg-accent-700/8'
            : isThreat
            ? 'bg-accent-700/12'
            : 'bg-emerald-700/8'
        )}
      />

      {/* SVG ring system */}
      <svg width={size} height={size} className="absolute inset-0 -rotate-90">
        {/* Tick marks around the ring */}
        <TickMarks size={size} radius={radius} isThreat={isThreat || mode === 'scanning'} />

        {/* Background track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.04)"
          strokeWidth={strokeWidth}
        />

        {/* Progress arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={mode === 'scanning' || isThreat ? '#D00000' : '#10b981'}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${dashValue} ${circumference}`}
          style={{
            filter:
              mode === 'scanning' || isThreat
                ? 'drop-shadow(0 0 6px rgba(208,0,0,0.6))'
                : 'drop-shadow(0 0 6px rgba(16,185,129,0.4))',
            transition: 'stroke-dasharray 0.1s linear',
          }}
        />
      </svg>

      {/* Inner content area */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {mode === 'scanning' ? (
          <div className="flex flex-col items-center gap-3">
            <span className="text-[10px] font-bold uppercase tracking-[0.25em] text-accent-500 animate-pulse">
              ANALYZING
            </span>
            <span className="text-6xl font-extrabold text-ink-50 tabular-nums">
              {Math.round(displayProgress)}%
            </span>
            <div className="flex flex-col items-center gap-1 mt-2 w-44">
              {SCAN_SECTIONS.map((section, i) => (
                <div
                  key={section.key}
                  className={cn(
                    'flex items-center gap-2 w-full text-[9px] font-semibold uppercase tracking-wider transition-all duration-300',
                    i < activeSection
                      ? 'text-ink-500'
                      : i === activeSection
                      ? 'text-accent-400'
                      : 'text-ink-700'
                  )}
                >
                  <span
                    className={cn(
                      'h-1 w-1 rounded-full transition-all',
                      i < activeSection
                        ? 'bg-ink-600'
                        : i === activeSection
                        ? 'bg-accent-500 accent-glow-sm'
                        : 'bg-base-400'
                    )}
                  />
                  {section.label}
                  {i < activeSection && <span className="ml-auto text-ink-700 mono">DONE</span>}
                  {i === activeSection && (
                    <span className="ml-auto text-accent-500 mono animate-pulse">...</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-1">
            <span
              className={cn(
                'text-[10px] font-bold uppercase tracking-[0.25em]',
                isThreat ? 'text-accent-500' : 'text-emerald-500'
              )}
            >
              {riskLevel}
            </span>
            <span
              className={cn(
                'text-7xl font-extrabold tabular-nums',
                isThreat ? 'text-ink-50' : 'text-emerald-100'
              )}
            >
              {Math.round(displayScore)}
            </span>
            <span
              className={cn(
                'text-sm font-bold uppercase tracking-[0.15em] mt-1',
                isThreat ? 'text-accent-400' : 'text-emerald-400'
              )}
            >
              {threatType}
            </span>
          </div>
        )}
      </div>

      {/* Scanning sweep line */}
      {mode === 'scanning' && (
        <div
          className="absolute inset-0 rounded-full animate-scan-rotate"
          style={{
            background:
              'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(208,0,0,0.08) 330deg, rgba(208,0,0,0.15) 350deg, transparent 360deg)',
          }}
        />
      )}
    </div>
  );
}

function TickMarks({ size, radius, isThreat }: { size: number; radius: number; isThreat: boolean }) {
  const ticks = 60;
  const tickElements = [];
  for (let i = 0; i < ticks; i++) {
    const angle = (i / ticks) * 2 * Math.PI;
    const inner = radius - 8;
    const outer = radius - 2;
    const x1 = size / 2 + inner * Math.cos(angle);
    const y1 = size / 2 + inner * Math.sin(angle);
    const x2 = size / 2 + outer * Math.cos(angle);
    const y2 = size / 2 + outer * Math.sin(angle);
    const major = i % 5 === 0;
    tickElements.push(
      <line
        key={i}
        x1={x1}
        y1={y1}
        x2={x2}
        y2={y2}
        stroke={isThreat ? 'rgba(208,0,0,0.15)' : 'rgba(255,255,255,0.08)'}
        strokeWidth={major ? 1.5 : 0.75}
      />
    );
  }
  return <>{tickElements}</>;
}
