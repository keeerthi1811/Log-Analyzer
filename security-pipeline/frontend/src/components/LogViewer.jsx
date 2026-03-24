/**
 * Log Viewer Component — Code-editor-style display
 * Renders logs with line numbers, risk highlighting, and finding markers.
 */
import React, { useState, useMemo, useRef, useEffect } from 'react';

const RISK_COLORS = {
  critical: { bg: '#fef2f2', border: '#ef4444', text: '#991b1b', badge: '#dc2626' },
  high: { bg: '#fff7ed', border: '#f97316', text: '#9a3412', badge: '#ea580c' },
  medium: { bg: '#fffbeb', border: '#f59e0b', text: '#92400e', badge: '#d97706' },
  low: { bg: '#f0fdf4', border: '#22c55e', text: '#166534', badge: '#16a34a' },
  info: { bg: '#f0f9ff', border: '#3b82f6', text: '#1e40af', badge: '#2563eb' },
};

const LogViewer = ({ content, findings }) => {
  const [selectedLine, setSelectedLine] = useState(null);
  const [filter, setFilter] = useState('all'); // 'all' | 'critical' | 'high' | 'medium' | 'low'
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef(null);

  const lines = useMemo(() => (content || '').split('\n'), [content]);

  // Create a findings map by line number for O(1) lookup
  const findingsMap = useMemo(() => {
    const map = {};
    (findings || []).forEach((f) => {
      if (!map[f.line]) map[f.line] = [];
      map[f.line].push(f);
    });
    return map;
  }, [findings]);

  // Filter findings
  const visibleFindings = useMemo(() => {
    if (filter === 'all') return findings || [];
    return (findings || []).filter((f) => f.risk === filter);
  }, [findings, filter]);

  const visibleFindingLines = new Set(visibleFindings.map((f) => f.line));

  // Scroll to finding on click
  const scrollToLine = (lineNum) => {
    setSelectedLine(lineNum);
    const el = document.getElementById(`log-line-${lineNum}`);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  // Count findings by risk
  const riskCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    (findings || []).forEach((f) => {
      if (counts[f.risk] !== undefined) counts[f.risk]++;
    });
    return counts;
  }, [findings]);

  const getHighestRisk = (lineFindings) => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    for (const risk of order) {
      if (lineFindings.some((f) => f.risk === risk)) return risk;
    }
    return 'info';
  };

  return (
    <div className="log-viewer">
      <div className="log-viewer-header">
        <h3>📄 Log Analysis View</h3>
        <div className="log-toolbar">
          {/* Search */}
          <input
            type="text"
            className="log-search"
            placeholder="Search logs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          {/* Filter buttons */}
          <div className="filter-buttons">
            <button
              className={`filter-btn ${filter === 'all' ? 'filter-active' : ''}`}
              onClick={() => setFilter('all')}
            >
              All ({findings?.length || 0})
            </button>
            {Object.entries(riskCounts).map(
              ([risk, count]) =>
                count > 0 && (
                  <button
                    key={risk}
                    className={`filter-btn filter-${risk} ${filter === risk ? 'filter-active' : ''}`}
                    onClick={() => setFilter(risk)}
                  >
                    {risk} ({count})
                  </button>
                )
            )}
          </div>
        </div>
      </div>

      {/* Findings Quick Nav */}
      {findings && findings.length > 0 && (
        <div className="findings-nav">
          {findings.map((f, idx) => (
            <button
              key={idx}
              className={`finding-nav-btn finding-nav-${f.risk}`}
              onClick={() => scrollToLine(f.line)}
              title={`Line ${f.line}: ${f.type} (${f.risk})`}
            >
              L{f.line}
            </button>
          ))}
        </div>
      )}

      {/* Log Content */}
      <div className="log-container" ref={containerRef}>
        {lines.map((line, index) => {
          const lineNum = index + 1;
          const lineFindings = findingsMap[lineNum] || [];
          const hasFindings = lineFindings.length > 0;
          const isVisible =
            filter === 'all' || visibleFindingLines.has(lineNum);
          const highestRisk = hasFindings ? getHighestRisk(lineFindings) : null;
          const colors = highestRisk ? RISK_COLORS[highestRisk] : null;
          const isSelected = selectedLine === lineNum;

          // Search highlight
          const matchesSearch =
            searchTerm && line.toLowerCase().includes(searchTerm.toLowerCase());

          // Skip non-matching lines when filtering (but show surrounding context)
          if (filter !== 'all' && !isVisible && !hasFindings) {
            return null;
          }

          return (
            <div
              key={lineNum}
              id={`log-line-${lineNum}`}
              className={`log-line ${hasFindings ? 'log-line-finding' : ''} ${
                isSelected ? 'log-line-selected' : ''
              } ${matchesSearch ? 'log-line-search-match' : ''}`}
              style={
                hasFindings
                  ? {
                      backgroundColor: colors.bg,
                      borderLeft: `4px solid ${colors.border}`,
                    }
                  : {}
              }
              onClick={() => hasFindings && setSelectedLine(lineNum)}
            >
              {/* Line Number */}
              <span className="line-number">{lineNum}</span>

              {/* Risk Indicator */}
              {hasFindings && (
                <span
                  className="risk-indicator"
                  style={{ backgroundColor: colors.badge }}
                >
                  {highestRisk === 'critical'
                    ? '🔴'
                    : highestRisk === 'high'
                    ? '🟠'
                    : highestRisk === 'medium'
                    ? '🟡'
                    : '🟢'}
                </span>
              )}

              {/* Line Content */}
              <span className="line-content">
                {searchTerm ? highlightSearch(line, searchTerm) : line}
              </span>

              {/* Risk Badges */}
              {hasFindings && (
                <span className="risk-badges">
                  {lineFindings.map((f, i) => (
                    <span
                      key={i}
                      className="risk-badge"
                      style={{
                        backgroundColor: RISK_COLORS[f.risk]?.badge,
                        color: '#fff',
                      }}
                    >
                      {f.risk.toUpperCase()}: {f.type}
                    </span>
                  ))}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Selected Line Detail */}
      {selectedLine && findingsMap[selectedLine] && (
        <div className="line-detail-panel">
          <h4>
            🔍 Line {selectedLine} — Findings Detail
            <button className="close-btn" onClick={() => setSelectedLine(null)}>
              ✕
            </button>
          </h4>
          {findingsMap[selectedLine].map((f, idx) => (
            <div key={idx} className="finding-detail">
              <div className="finding-detail-header">
                <span
                  className="risk-badge-lg"
                  style={{
                    backgroundColor: RISK_COLORS[f.risk]?.badge,
                    color: '#fff',
                  }}
                >
                  {f.risk.toUpperCase()}
                </span>
                <span className="finding-type">{f.type}</span>
              </div>
              <div className="finding-detail-body">
                <div>
                  <strong>Value:</strong>{' '}
                  <code className="finding-value">{f.value}</code>
                </div>
                {f.recommendation && (
                  <div className="finding-recommendation">
                    <strong>📋 Recommendation:</strong> {f.recommendation}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Stats Footer */}
      <div className="log-footer">
        <span>
          {lines.length} lines • {findings?.length || 0} findings
        </span>
        {filter !== 'all' && (
          <span>
            Filtering: {filter} ({visibleFindings.length} shown)
          </span>
        )}
      </div>
    </div>
  );
};

// Helper: highlight search matches in text
function highlightSearch(text, term) {
  if (!term) return text;
  const parts = text.split(new RegExp(`(${escapeRegExp(term)})`, 'gi'));
  return parts.map((part, i) =>
    part.toLowerCase() === term.toLowerCase() ? (
      <mark key={i} className="search-highlight">
        {part}
      </mark>
    ) : (
      part
    )
  );
}

function escapeRegExp(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export default LogViewer;