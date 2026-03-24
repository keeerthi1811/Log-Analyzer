/**
 * Insights Panel — Displays AI-generated analysis
 * Shows summary, anomalies, security warnings, and risk assessment.
 */
import React, { useState } from 'react';

const InsightsPanel = ({ insights, findings }) => {
  const [expandedSection, setExpandedSection] = useState({
    summary: true,
    anomalies: true,
    warnings: true,
    assessment: true,
    findings: false,
  });

  const toggle = (section) => {
    setExpandedSection((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  if (!insights) {
    return (
      <div className="insights-panel">
        <h3>🤖 AI Insights</h3>
        <p className="insights-empty">No AI insights available. Enable AI Insights in options.</p>
      </div>
    );
  }

  const findingsByType = {};
  (findings || []).forEach((f) => {
    if (!findingsByType[f.type]) findingsByType[f.type] = [];
    findingsByType[f.type].push(f);
  });

  return (
    <div className="insights-panel">
      <h3>🤖 AI Security Insights</h3>

      {/* Summary */}
      <div className="insight-section">
        <button className="insight-header" onClick={() => toggle('summary')}>
          <span>📊 Summary</span>
          <span>{expandedSection.summary ? '▼' : '▶'}</span>
        </button>
        {expandedSection.summary && (
          <div className="insight-body">
            <p>{insights.summary || 'No summary available.'}</p>
          </div>
        )}
      </div>

      {/* Anomalies */}
      {insights.anomalies && insights.anomalies.length > 0 && (
        <div className="insight-section insight-anomalies">
          <button className="insight-header" onClick={() => toggle('anomalies')}>
            <span>🔍 Detected Anomalies ({insights.anomalies.length})</span>
            <span>{expandedSection.anomalies ? '▼' : '▶'}</span>
          </button>
          {expandedSection.anomalies && (
            <div className="insight-body">
              <ul className="anomaly-list">
                {insights.anomalies.map((anomaly, idx) => (
                  <li key={idx} className="anomaly-item">
                    <span className="anomaly-icon">⚠️</span>
                    <span>{anomaly}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Security Warnings */}
      {insights.security_warnings && insights.security_warnings.length > 0 && (
        <div className="insight-section insight-warnings">
          <button className="insight-header" onClick={() => toggle('warnings')}>
            <span>🛡️ Security Warnings ({insights.security_warnings.length})</span>
            <span>{expandedSection.warnings ? '▼' : '▶'}</span>
          </button>
          {expandedSection.warnings && (
            <div className="insight-body">
              {insights.security_warnings.map((warning, idx) => (
                <div key={idx} className="warning-card">
                  <div className="warning-icon">🚨</div>
                  <div className="warning-text">{warning}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Risk Assessment */}
      {insights.risk_assessment && (
        <div className="insight-section insight-assessment">
          <button className="insight-header" onClick={() => toggle('assessment')}>
            <span>📈 Risk Assessment</span>
            <span>{expandedSection.assessment ? '▼' : '▶'}</span>
          </button>
          {expandedSection.assessment && (
            <div className="insight-body">
              <p className="assessment-text">{insights.risk_assessment}</p>
            </div>
          )}
        </div>
      )}

      {/* Findings Breakdown by Type */}
      <div className="insight-section">
        <button className="insight-header" onClick={() => toggle('findings')}>
          <span>📋 Findings by Category ({Object.keys(findingsByType).length})</span>
          <span>{expandedSection.findings ? '▼' : '▶'}</span>
        </button>
        {expandedSection.findings && (
          <div className="insight-body">
            {Object.entries(findingsByType).map(([type, items]) => (
              <div key={type} className="category-group">
                <div className="category-header">
                  <span className="category-name">{type.replace(/_/g, ' ')}</span>
                  <span className="category-count">{items.length}</span>
                </div>
                {items.map((f, idx) => (
                  <div key={idx} className="category-item">
                    <span className={`mini-badge risk-${f.risk}`}>{f.risk}</span>
                    <span>
                      Line {f.line}: <code>{f.value.substring(0, 40)}</code>
                    </span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default InsightsPanel;