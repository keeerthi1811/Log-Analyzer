/**
 * Risk Summary Dashboard
 * Displays overall risk score, breakdown, and key metrics.
 */
import React from 'react';

const RiskSummary = ({ result }) => {
  if (!result) return null;

  const { risk_score, risk_breakdown, findings, total_lines, blocked, processing_time_ms, status } =
    result;

  // Determine overall risk color
  const getScoreColor = (score) => {
    if (score >= 15) return '#dc2626'; // red
    if (score >= 10) return '#ea580c'; // orange
    if (score >= 5) return '#d97706'; // amber
    return '#16a34a'; // green
  };

  const getScoreLabel = (score) => {
    if (score >= 15) return 'CRITICAL RISK';
    if (score >= 10) return 'HIGH RISK';
    if (score >= 5) return 'MODERATE RISK';
    if (score > 0) return 'LOW RISK';
    return 'CLEAN';
  };

  const scoreColor = getScoreColor(risk_score);

  const riskBars = [
    { label: 'Critical', count: risk_breakdown.critical, color: '#dc2626', points: 5 },
    { label: 'High', count: risk_breakdown.high, color: '#ea580c', points: 4 },
    { label: 'Medium', count: risk_breakdown.medium, color: '#d97706', points: 2 },
    { label: 'Low', count: risk_breakdown.low, color: '#16a34a', points: 1 },
  ];

  const maxCount = Math.max(...riskBars.map((r) => r.count), 1);

  return (
    <div className="risk-summary">
      {/* Blocked Banner */}
      {blocked && (
        <div className="blocked-banner">
          🚫 CONTENT BLOCKED — High-risk findings triggered the blocking policy
        </div>
      )}

      <div className="risk-summary-grid">
        {/* Risk Score Circle */}
        <div className="risk-score-card">
          <div className="risk-score-circle" style={{ borderColor: scoreColor }}>
            <span className="risk-score-number" style={{ color: scoreColor }}>
              {risk_score}
            </span>
            <span className="risk-score-label">Risk Score</span>
          </div>
          <div className="risk-score-assessment" style={{ color: scoreColor }}>
            {getScoreLabel(risk_score)}
          </div>
        </div>

        {/* Risk Breakdown Bars */}
        <div className="risk-breakdown-card">
          <h4>Risk Breakdown</h4>
          {riskBars.map((bar) => (
            <div key={bar.label} className="risk-bar-row">
              <span className="risk-bar-label">
                {bar.label}
                <span className="risk-bar-count">{bar.count}</span>
              </span>
              <div className="risk-bar-track">
                <div
                  className="risk-bar-fill"
                  style={{
                    width: `${(bar.count / maxCount) * 100}%`,
                    backgroundColor: bar.color,
                    minWidth: bar.count > 0 ? '8px' : '0',
                  }}
                />
              </div>
              <span className="risk-bar-points">{bar.count * bar.points} pts</span>
            </div>
          ))}
        </div>

        {/* Metrics Cards */}
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-value">{total_lines}</div>
            <div className="metric-label">Lines Analyzed</div>
          </div>
          <div className="metric-card">
            <div className="metric-value">{findings?.length || 0}</div>
            <div className="metric-label">Findings</div>
          </div>
          <div className="metric-card">
            <div className="metric-value">{processing_time_ms}ms</div>
            <div className="metric-label">Processing Time</div>
          </div>
          <div className="metric-card">
            <div className={`metric-value ${status === 'warning' ? 'metric-warning' : 'metric-ok'}`}>
              {status === 'warning' ? '⚠️' : '✅'} {status}
            </div>
            <div className="metric-label">Status</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RiskSummary;