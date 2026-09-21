import {
  RADAR_AXES,
  pointsAttr,
  radarPoint,
  type DimensionKey,
  type ResolvedRiskDimensions,
} from '@/lib/investigationView';

/**
 * Presentational-only three-axis radar (plain SVG, no chart dependency).
 * It plots the three values it is given and nothing else: an axis whose
 * value is null is drawn as an empty axis labelled UNAVAILABLE — never as
 * 0 — and the filled area is only drawn when all three values exist.
 */

// Dimension identity colours. Deliberately NOT green/amber/red: colour here
// identifies the axis, it never encodes severity, so a low-risk email does
// not look "safe green" and a high-risk one is not implied by hue alone.
export const DIMENSION_COLORS: Record<DimensionKey, string> = {
  overall: 'rgb(var(--ink-100))', // theme-aware (near-white in dark, near-black in light)
  forensic: '#60a5fa',
  content: '#e879f9',
};

const CX = 170;
const CY = 150;
const R = 96;
const RINGS = [25, 50, 75, 100];

const AXIS_LABEL: Record<DimensionKey, { text: string; dx: number; dy: number }> = {
  overall: { text: 'Overall Risk', dx: 0, dy: -16 },
  content: { text: 'Content / Semantic', dx: 0, dy: 20 },
  forensic: { text: 'Forensic / Technical', dx: 0, dy: 20 },
};

export function RiskRadar({ dims }: { dims: ResolvedRiskDimensions }) {
  const valueOf = (key: DimensionKey) => dims[key].value;
  const allAvailable = RADAR_AXES.every((a) => valueOf(a.key) !== null);

  const describe = RADAR_AXES.map((a) => {
    const v = valueOf(a.key);
    return `${dims[a.key].label} ${v === null ? 'unavailable' : `${v} out of 100`}`;
  }).join(', ');

  const dataPoints = RADAR_AXES.map((a) => radarPoint(CX, CY, R, a.angleDeg, valueOf(a.key) ?? 0));

  return (
    <svg
      viewBox="0 0 340 250"
      role="img"
      aria-label={`Three-axis risk chart: ${describe}`}
      className="block w-full max-w-[340px] h-auto mx-auto"
    >
      {/* Grid rings */}
      {RINGS.map((ring) => (
        <polygon
          key={ring}
          points={pointsAttr(RADAR_AXES.map((a) => radarPoint(CX, CY, R, a.angleDeg, ring)))}
          fill="none"
          style={{ stroke: 'rgb(var(--base-300) / 0.55)' }}
          strokeWidth={ring === 100 ? 1.2 : 0.8}
        />
      ))}

      {/* Axes */}
      {RADAR_AXES.map((a) => {
        const end = radarPoint(CX, CY, R, a.angleDeg, 100);
        return (
          <line
            key={a.key}
            x1={CX}
            y1={CY}
            x2={end.x}
            y2={end.y}
            style={{ stroke: 'rgb(var(--base-300) / 0.55)' }}
            strokeWidth={0.8}
          />
        );
      })}

      {/* Scale labels along the Overall axis */}
      {RINGS.map((ring) => (
        <text
          key={ring}
          x={CX + 5}
          y={CY - (ring / 100) * R + 3}
          fontSize={9}
          style={{ fill: 'rgb(var(--ink-500))' }}
        >
          {ring}
        </text>
      ))}

      {/* Data area — only when every axis has a real value */}
      {allAvailable && (
        <polygon
          points={pointsAttr(dataPoints)}
          fill="rgba(56,189,248,0.16)"
          stroke="#38bdf8"
          strokeWidth={1.5}
          strokeLinejoin="round"
        />
      )}

      {/* Data points */}
      {RADAR_AXES.map((a, i) => {
        if (valueOf(a.key) === null) return null;
        return (
          <circle
            key={a.key}
            cx={dataPoints[i].x}
            cy={dataPoints[i].y}
            r={4}
            style={{ fill: DIMENSION_COLORS[a.key], stroke: 'rgb(var(--base-900))' }}
            strokeWidth={1.2}
          />
        );
      })}

      {/* Axis labels */}
      {RADAR_AXES.map((a) => {
        const vertex = radarPoint(CX, CY, R, a.angleDeg, 100);
        const label = AXIS_LABEL[a.key];
        const unavailable = valueOf(a.key) === null;
        // The top label moves up when it carries a second (UNAVAILABLE) line, so it never sits on the vertex.
        const dy = a.key === 'overall' && unavailable ? label.dy - 13 : label.dy;
        return (
          <g key={a.key}>
            <text
              x={vertex.x + label.dx}
              y={vertex.y + dy}
              textAnchor="middle"
              fontSize={12}
              style={{ fill: 'rgb(var(--ink-300))' }}
            >
              {label.text}
            </text>
            {unavailable && (
              <text
                x={vertex.x + label.dx}
                y={vertex.y + dy + 13}
                textAnchor="middle"
                fontSize={10}
                fontWeight={700}
                letterSpacing={0.6}
                style={{ fill: 'rgb(var(--ink-500))' }}
              >
                UNAVAILABLE
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}
