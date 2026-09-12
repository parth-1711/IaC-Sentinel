'use client';

import { useState, useMemo } from 'react';

export default function ViolationTable({ violations = [], onSelectViolation }) {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [selectedSeverity, setSelectedSeverity] = useState('all');

  const filteredViolations = useMemo(() => {
    return violations.filter(v => {
      const matchSearch = 
        (v.rule && v.rule.toLowerCase().includes(search.toLowerCase())) ||
        (v.resource && v.resource.toLowerCase().includes(search.toLowerCase())) ||
        (v.message && v.message.toLowerCase().includes(search.toLowerCase()));

      const matchCategory = selectedCategory === 'all' || v.category === selectedCategory;
      const matchSeverity = selectedSeverity === 'all' || v.severity === selectedSeverity;

      return matchSearch && matchCategory && matchSeverity;
    });
  }, [violations, search, selectedCategory, selectedSeverity]);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem' }}>
      <div className="section-header">
        <h2 className="section-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
          </svg>
          Active Compliance Violations Explorer
        </h2>
        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
          Showing {filteredViolations.length} of {violations.length} findings
        </span>
      </div>

      {/* Controls: Search and Filters */}
      <div className="controls-bar">
        <input
          type="text"
          placeholder="Filter by rule, resource address, or keyword..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="search-input"
        />

        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* Category Filter */}
          <div className="filter-btn-group">
            {['all', 'security', 'cost', 'governance'].map(cat => (
              <button
                key={cat}
                className={`filter-btn ${selectedCategory === cat ? 'active' : ''}`}
                onClick={() => setSelectedCategory(cat)}
              >
                {cat.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Severity Filter */}
          <div className="filter-btn-group">
            {['all', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                className={`filter-btn ${selectedSeverity === sev ? 'active' : ''}`}
                onClick={() => setSelectedSeverity(sev)}
              >
                {sev.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Category</th>
              <th>Rule</th>
              <th>Resource Address</th>
              <th>Violation Detail</th>
              <th style={{ textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredViolations.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                  No violations match the selected filters.
                </td>
              </tr>
            ) : (
              filteredViolations.map((v, i) => {
                const badgeClass = v.severity === 'high' ? 'badge-high' : (v.severity === 'medium' ? 'badge-medium' : 'badge-low');
                return (
                  <tr key={v.id || i} onClick={() => onSelectViolation(v)}>
                    <td>
                      <span className={`badge ${badgeClass}`}>{v.severity}</span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                        {v.category}
                      </span>
                    </td>
                    <td>
                      <code className="inline-code">{v.rule}</code>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.825rem', color: 'var(--text-primary)' }}>
                      {v.resource}
                    </td>
                    <td style={{ maxWidth: '360px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {v.message}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button 
                        className="filter-btn" 
                        style={{ background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-cyan)', border: '1px solid rgba(56, 189, 248, 0.3)' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectViolation(v);
                        }}
                      >
                        Inspect AI Fix &rarr;
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
