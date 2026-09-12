'use client';

import { useState } from 'react';

export default function ViolationModal({ violation, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!violation) return null;

  const handleCopy = () => {
    if (violation.patch) {
      navigator.clipboard.writeText(violation.patch);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const sevBadge = violation.severity === 'high' ? 'badge-high' : (violation.severity === 'medium' ? 'badge-medium' : 'badge-low');

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>&times;</button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <span className={`badge ${sevBadge}`}>{violation.severity}</span>
          <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: 'var(--text-secondary)' }}>{violation.category}</span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-muted)' }}>{violation.violation_id || violation.id}</span>
        </div>

        <h2 style={{ fontSize: '1.35rem', fontWeight: '700', marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
          {violation.rule}
        </h2>

        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginBottom: '1.25rem' }}>
          {violation.message}
        </p>

        <div style={{ background: 'var(--bg-surface-elevated)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-md)', marginBottom: '1.5rem', border: '1px solid var(--border-subtle)' }}>
          <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', fontWeight: '600' }}>Offending Resource</span>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
            {violation.resource}
          </div>
          {violation.file && (
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              File: <code className="inline-code">{violation.file}</code>
            </div>
          )}
        </div>

        {/* AI Explanation */}
        <div style={{ marginBottom: '1.5rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--accent-indigo)', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm1 15h-2v-6h2zm0-8h-2V7h2z" />
            </svg>
            AI Risk & Threat Analysis
          </h3>
          <div style={{ background: 'rgba(99, 102, 241, 0.06)', border: '1px solid rgba(99, 102, 241, 0.2)', borderRadius: 'var(--radius-md)', padding: '1rem', fontSize: '0.875rem', lineHeight: '1.6', color: '#e2e8f0', whiteSpace: 'pre-line' }}>
            {violation.explanation || "This rule flags configuration patterns that expose resources to unauthorized public access or non-compliant cloud states."}
          </div>
        </div>

        {/* AI Suggested HCL Patch */}
        {violation.patch && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: '600', color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
                Suggested Terraform Patch (HCL)
              </h3>
              <button onClick={handleCopy} className="filter-btn" style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)' }}>
                {copied ? 'Copied!' : 'Copy HCL'}
              </button>
            </div>
            <pre className="code-box">
              <code>{violation.patch}</code>
            </pre>
          </div>
        )}

        <div style={{ marginTop: '2rem', display: 'flex', justifyContent: 'flex-end' }}>
          <button 
            onClick={onClose}
            className="filter-btn"
            style={{ background: 'var(--accent-cyan)', color: '#090d16', padding: '0.6rem 1.25rem', fontSize: '0.85rem' }}
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}
