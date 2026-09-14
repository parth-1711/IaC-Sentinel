import React from 'react';

// Mirrors the weights in calculate_compliance_score() (scanner/parse_violations.py),
// but without the max(0, ...) floor. The official compliance_score intentionally
// saturates at 0 once violations are severe enough — correct for the headline
// metric, but it means this chart would go flat at 0 even while the underlying
// violation mix is genuinely improving. Plotting the uncapped version keeps
// relative progress visible below that floor, using fields already stored on
// every scan (no backend change or re-scan needed to see it retroactively).
function rawScore(scan) {
  return 100 - (scan.high_count * 25 + scan.medium_count * 10 + scan.low_count * 5);
}

export default function TrendChart({ scans = [] }) {
  // Sort chronologically for trend
  const chronological = [...scans].reverse();

  if (chronological.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <p style={{ color: 'var(--text-muted)' }}>No historical scan telemetry available</p>
      </div>
    );
  }

  const width = 600;
  const height = 180;
  const paddingX = 40;
  const paddingY = 25;

  const rawScores = chronological.map(rawScore);
  const minRaw = Math.min(0, ...rawScores);
  const maxRaw = 100;
  const range = maxRaw - minRaw;

  const points = chronological.map((scan, i) => {
    const x = paddingX + (i / Math.max(1, chronological.length - 1)) * (width - paddingX * 2);
    const raw = rawScore(scan);
    const y = height - paddingY - ((raw - minRaw) / range) * (height - paddingY * 2);
    return { x, y, raw, scan };
  });

  const pathD = points.reduce((acc, pt, i) => {
    return i === 0 ? `M ${pt.x} ${pt.y}` : `${acc} L ${pt.x} ${pt.y}`;
  }, '');

  const gridTicks = 4;
  const gridValues = Array.from({ length: gridTicks + 1 }, (_, i) =>
    Math.round(minRaw + (range * i) / gridTicks)
  );

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="section-header">
        <h2 className="section-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="2">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
          </svg>
          Compliance Risk Trend Over Time
        </h2>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Past {scans.length} PR Executions</span>
      </div>

      <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '-0.75rem', marginBottom: '1rem' }}>
        Uncapped composite risk score — the headline Compliance Health score
        (shown above) floors at 0 once violations are this severe; this line
        shows relative movement below that floor.
      </p>

      <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto', minHeight: '180px' }}>
          <defs>
            <linearGradient id="scoreGlow" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {gridValues.map((val) => {
            const y = height - paddingY - ((val - minRaw) / range) * (height - paddingY * 2);
            return (
              <g key={val}>
                <line x1={paddingX} y1={y} x2={width - paddingX} y2={y} stroke="rgba(255,255,255,0.06)" strokeDasharray="3 3" />
                <text x={paddingX - 8} y={y + 3} fill="var(--text-muted)" fontSize="9" textAnchor="end" fontFamily="var(--font-mono)">
                  {val}
                </text>
              </g>
            );
          })}

          {/* Area fill */}
          {points.length > 1 && (
            <path
              d={`${pathD} L ${points[points.length - 1].x} ${height - paddingY} L ${points[0].x} ${height - paddingY} Z`}
              fill="url(#scoreGlow)"
            />
          )}

          {/* Line */}
          <path d={pathD} fill="none" stroke="var(--accent-cyan)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />

          {/* Data points */}
          {points.map((pt, i) => (
            <g key={i}>
              <circle cx={pt.x} cy={pt.y} r="5" fill="#0f172a" stroke="var(--accent-cyan)" strokeWidth="2.5" />
              <text
                x={pt.x}
                y={pt.y - 10}
                fill="var(--text-primary)"
                fontSize="10"
                fontWeight="600"
                textAnchor="middle"
                fontFamily="var(--font-mono)"
              >
                {pt.raw}
              </text>
              <text
                x={pt.x}
                y={height - 8}
                fill="var(--text-muted)"
                fontSize="9"
                textAnchor="middle"
              >
                PR #{pt.scan.pr_number || (i + 1)}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
