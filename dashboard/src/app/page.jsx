'use client';

import { useState, useEffect } from 'react';
import { useSession } from 'next-auth/react';
import Header from '../components/Header';
import MetricsGrid from '../components/MetricsGrid';
import TrendChart from '../components/TrendChart';
import CategoryBreakdown from '../components/CategoryBreakdown';
import ViolationTable from '../components/ViolationTable';
import ViolationModal from '../components/ViolationModal';

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedRepo, setSelectedRepo] = useState('all');
  const [activeViolation, setActiveViolation] = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/scans', { cache: 'no-store' });
      if (!res.ok) {
        throw new Error(
          res.status === 401
            ? 'Session expired — please sign in again.'
            : 'Failed to load compliance audit logs'
        );
      }
      const json = await res.json();
      setData(json);
      if (json.scans && json.scans.length > 0 && !selectedScanId) {
        setSelectedScanId(json.scans[0].id);
      }
      setError(null);
    } catch (err) {
      console.error(err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (status === 'authenticated') {
      loadData();
    }
  }, [status]);

  if (status === 'loading') {
    return (
      <div className="auth-screen">
        <div style={{ color: 'var(--text-muted)', textAlign: 'center' }}>
          <div style={{ display: 'inline-block', width: '28px', height: '28px', border: '3px solid var(--accent-cyan)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
          <p style={{ marginTop: '1rem' }}>Checking session...</p>
        </div>
      </div>
    );
  }

  // Middleware already redirects unauthenticated requests to /login, this is
  // just a safety net against a stale client-rendered tree.
  if (status !== 'authenticated') {
    return null;
  }

  const scans = data?.scans || [];
  const repoOptions = [...new Set(scans.map(s => s.repo))].sort();
  const filteredScans = selectedRepo === 'all' ? scans : scans.filter(s => s.repo === selectedRepo);
  const currentScan = filteredScans.find(s => s.id === selectedScanId) || filteredScans[0];

  // All violations from current scan
  const activeViolations = currentScan?.violations || [];

  const handleSelectRepo = (repo) => {
    setSelectedRepo(repo);
    // Force re-selection to the newest scan within the newly filtered set,
    // rather than keeping a scan id that may belong to a different repo.
    setSelectedScanId(null);
  };

  return (
    <div>
      <Header
        lastUpdated={data?.last_updated}
        totalScans={scans.length}
        onRefresh={loadData}
        user={session?.user}
      />

      <main className="dashboard-container">
        {loading && !data ? (
          <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <div style={{ display: 'inline-block', width: '28px', height: '28px', border: '3px solid var(--accent-cyan)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }}></div>
            <p style={{ marginTop: '1rem' }}>Loading IaC Sentinel Compliance Telemetry...</p>
          </div>
        ) : error ? (
          <div className="glass-panel" style={{ padding: '2rem', borderColor: 'var(--accent-rose)' }}>
            <h3 style={{ color: 'var(--accent-rose)', marginBottom: '0.5rem' }}>Failed to Load Telemetry</h3>
            <p style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        ) : scans.length === 0 ? (
          <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            <p>No compliance scans found for repositories you have access to.</p>
          </div>
        ) : (
          <>
            {/* Repository Filter Bar */}
            {repoOptions.length > 1 && (
              <div className="glass-panel" style={{ padding: '1rem 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <span style={{ fontSize: '0.875rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                  Repository:
                </span>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <button
                    onClick={() => handleSelectRepo('all')}
                    className={`filter-btn ${selectedRepo === 'all' ? 'active' : ''}`}
                    style={{
                      background: selectedRepo === 'all' ? 'var(--accent-cyan)' : 'var(--bg-surface-elevated)',
                      color: selectedRepo === 'all' ? '#090d16' : 'var(--text-secondary)',
                      border: '1px solid var(--border-subtle)',
                      padding: '0.45rem 0.85rem'
                    }}
                  >
                    All Repositories
                  </button>
                  {repoOptions.map(repo => {
                    const isSelected = repo === selectedRepo;
                    return (
                      <button
                        key={repo}
                        onClick={() => handleSelectRepo(repo)}
                        className={`filter-btn ${isSelected ? 'active' : ''}`}
                        style={{
                          background: isSelected ? 'var(--accent-cyan)' : 'var(--bg-surface-elevated)',
                          color: isSelected ? '#090d16' : 'var(--text-secondary)',
                          border: '1px solid var(--border-subtle)',
                          padding: '0.45rem 0.85rem'
                        }}
                      >
                        {repo}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Top Metrics Row */}
            <MetricsGrid
              latestScan={currentScan}
              totalScans={filteredScans.length}
            />

            {/* Middle Telemetry & Breakdown Row */}
            <div className="analysis-row">
              <TrendChart scans={filteredScans} />
              <CategoryBreakdown violations={activeViolations} />
            </div>

            {/* Scan Selector Bar if multiple scans exist */}
            {filteredScans.length > 1 && (
              <div className="glass-panel" style={{ padding: '1rem 1.5rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <span style={{ fontSize: '0.875rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                  Selected Execution Run:
                </span>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {filteredScans.map(s => {
                    const isSelected = s.id === currentScan?.id;
                    const badgeType = s.status === 'PASSED' ? 'badge-passed' : 'badge-failed';
                    return (
                      <button
                        key={s.id}
                        onClick={() => setSelectedScanId(s.id)}
                        className={`filter-btn ${isSelected ? 'active' : ''}`}
                        style={{
                          background: isSelected ? 'var(--accent-cyan)' : 'var(--bg-surface-elevated)',
                          color: isSelected ? '#090d16' : 'var(--text-secondary)',
                          border: '1px solid var(--border-subtle)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.4rem',
                          padding: '0.45rem 0.85rem'
                        }}
                      >
                        <span>{s.repo} (PR #{s.pr_number || s.id})</span>
                        <span className={`badge ${badgeType}`} style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>
                          {s.compliance_score}%
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Active Violations Table */}
            <ViolationTable
              violations={activeViolations}
              onSelectViolation={(v) => setActiveViolation(v)}
            />
          </>
        )}
      </main>

      {/* AI Remediation Detail Modal */}
      {activeViolation && (
        <ViolationModal
          violation={activeViolation}
          onClose={() => setActiveViolation(null)}
        />
      )}
    </div>
  );
}
