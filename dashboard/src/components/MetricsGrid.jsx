import React from 'react';

export default function MetricsGrid({ latestScan, totalScans, totalViolationsAcrossHistory }) {
  const score = latestScan ? latestScan.compliance_score : 100;
  const highCount = latestScan ? latestScan.high_count : 0;
  const totalViolations = latestScan ? latestScan.total_violations : 0;

  const scoreColor = score >= 85 ? 'var(--accent-emerald)' : (score >= 60 ? 'var(--accent-amber)' : 'var(--accent-rose)');

  return (
    <div className="metrics-grid">
      <div className="glass-panel metric-card">
        <div>
          <div className="metric-label">
            <span>Compliance Health</span>
            <span className="badge" style={{ background: `${scoreColor}20`, color: scoreColor }}>
              {score >= 85 ? 'HEALTHY' : (score >= 60 ? 'WARNING' : 'CRITICAL')}
            </span>
          </div>
          <div className="metric-value" style={{ color: scoreColor }}>
            {score}<span style={{ fontSize: '1.25rem', color: 'var(--text-muted)' }}>/100</span>
          </div>
        </div>
        <div className="metric-footer">
          <span>Based on latest scan evaluation</span>
        </div>
      </div>

      <div className="glass-panel metric-card">
        <div>
          <div className="metric-label">
            <span>High Severity Blockers</span>
            <span className="badge badge-high">CI Blocking</span>
          </div>
          <div className="metric-value" style={{ color: highCount > 0 ? 'var(--accent-rose)' : 'var(--accent-emerald)' }}>
            {highCount}
          </div>
        </div>
        <div className="metric-footer">
          <span>{highCount > 0 ? 'Must remediate before merge' : 'No blocker policies triggered'}</span>
        </div>
      </div>

      <div className="glass-panel metric-card">
        <div>
          <div className="metric-label">
            <span>Active Violations</span>
            <span className="badge badge-medium">Latest Run</span>
          </div>
          <div className="metric-value">
            {totalViolations}
          </div>
        </div>
        <div className="metric-footer">
          <span>Across Security, Cost & Governance</span>
        </div>
      </div>

      <div className="glass-panel metric-card">
        <div>
          <div className="metric-label">
            <span>Total Evaluated Scans</span>
            <span className="badge badge-low">Audit Log</span>
          </div>
          <div className="metric-value">
            {totalScans}
          </div>
        </div>
        <div className="metric-footer">
          <span>Logged in MongoDB audit store</span>
        </div>
      </div>
    </div>
  );
}
