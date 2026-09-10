import React from 'react';

export default function CategoryBreakdown({ violations = [] }) {
  const security = violations.filter(v => v.category === 'security').length;
  const cost = violations.filter(v => v.category === 'cost').length;
  const governance = violations.filter(v => v.category === 'governance').length;
  const total = Math.max(1, security + cost + governance);

  const secPct = Math.round((security / total) * 100);
  const costPct = Math.round((cost / total) * 100);
  const govPct = Math.round((governance / total) * 100);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div>
        <div className="section-header">
          <h2 className="section-title">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-indigo)" strokeWidth="2">
              <path d="M21.21 15.89A10 10 0 1 1 8 2.83" />
              <path d="M22 12A10 10 0 0 0 12 2v10z" />
            </svg>
            Violations By Pillar
          </h2>
        </div>

        {/* Progress Bar */}
        <div style={{ height: '10px', width: '100%', display: 'flex', borderRadius: '5px', overflow: 'hidden', background: 'rgba(255,255,255,0.06)', marginBottom: '1.5rem' }}>
          <div style={{ width: `${secPct}%`, background: 'var(--accent-rose)', transition: 'width 0.3s ease' }} title={`Security: ${security}`} />
          <div style={{ width: `${costPct}%`, background: 'var(--accent-amber)', transition: 'width 0.3s ease' }} title={`Cost: ${cost}`} />
          <div style={{ width: `${govPct}%`, background: 'var(--accent-cyan)', transition: 'width 0.3s ease' }} title={`Governance: ${governance}`} />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'var(--accent-rose)', display: 'inline-block' }}></span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Security Policies</span>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', fontSize: '0.9rem' }}>{security} <small style={{ color: 'var(--text-muted)' }}>({secPct}%)</small></span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'var(--accent-amber)', display: 'inline-block' }}></span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Cost Efficiency</span>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', fontSize: '0.9rem' }}>{cost} <small style={{ color: 'var(--text-muted)' }}>({costPct}%)</small></span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: '10px', height: '10px', borderRadius: '3px', background: 'var(--accent-cyan)', display: 'inline-block' }}></span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Cloud Governance</span>
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', fontSize: '0.9rem' }}>{governance} <small style={{ color: 'var(--text-muted)' }}>({govPct}%)</small></span>
          </div>
        </div>
      </div>

      <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.775rem', color: 'var(--text-muted)' }}>
        Target: Zero high-severity security violations prior to deployment.
      </div>
    </div>
  );
}
