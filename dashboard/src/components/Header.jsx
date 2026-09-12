'use client';

import { signOut } from 'next-auth/react';

export default function Header({ lastUpdated, totalScans, onRefresh, user }) {
  return (
    <header className="app-header">
      <div className="brand">
        <div className="brand-icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div>
          <h1 className="brand-title">IaC Sentinel</h1>
          <p className="brand-subtitle">AI-Augmented Terraform Compliance Engine</p>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent-emerald)', boxShadow: '0 0 8px var(--accent-emerald)', display: 'inline-block' }}></span>
          <span>Engine Active (OPA v1.20 + Gemini)</span>
        </div>

        <button
          onClick={onRefresh}
          className="filter-btn"
          style={{
            background: 'var(--bg-surface-elevated)',
            border: '1px solid var(--border-subtle)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.5rem 0.85rem'
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
          </svg>
          Refresh Data
        </button>

        {user && (
          <div className="user-badge">
            {user.image && <img src={user.image} alt={user.name || 'GitHub avatar'} />}
            <span>{user.name || user.email}</span>
            <button
              onClick={() => signOut({ callbackUrl: '/login' })}
              className="filter-btn"
              style={{ background: 'var(--bg-surface-elevated)', border: '1px solid var(--border-subtle)', padding: '0.4rem 0.75rem' }}
            >
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
