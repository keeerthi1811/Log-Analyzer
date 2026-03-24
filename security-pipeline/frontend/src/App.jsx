/**
 * Main Application Component
 * Orchestrates the security pipeline UI.
 */
import React, { useState, useEffect, useCallback } from "react";
import FileUpload from "./components/FileUpload";
import TextInput from "./components/TextInput";
import LogViewer from "./components/LogViewer";
import InsightsPanel from "./components/InsightsPanel";
import RiskSummary from "./components/RiskSummary";
import { analyzeContent, uploadFile, healthCheck } from "./services/api";

function App() {
  const [activeTab, setActiveTab] = useState("file"); // 'file' | 'text' | 'sql' | 'chat'
  const [analysisResult, setAnalysisResult] = useState(null);
  const [originalContent, setOriginalContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [backendStatus, setBackendStatus] = useState(null);
  const [options, setOptions] = useState({
    mask: false,
    blockHighRisk: false,
    logAnalysis: true,
    aiInsights: true,
    chunkSize: 500,
  });

  // Health check on mount
  useEffect(() => {
    healthCheck()
      .then((data) => setBackendStatus(data))
      .catch(() => setBackendStatus({ status: "offline" }));
  }, []);

  const handleAnalyze = useCallback(
    async (inputType, content) => {
      setLoading(true);
      setError(null);
      setOriginalContent(content);

      try {
        const result = await analyzeContent(inputType, content, options);
        setAnalysisResult(result);
      } catch (err) {
        const msg =
          err.response?.data?.detail ||
          err.message ||
          "Analysis failed. Check backend connection.";
        setError(msg);
        setAnalysisResult(null);
      } finally {
        setLoading(false);
      }
    },
    [options]
  );

  const handleFileUpload = useCallback(
    async (file) => {
      setLoading(true);
      setError(null);

      try {
        const result = await uploadFile(file, options);
        console.log("Upload result:", result);
        console.log("Upload result KEYS:", Object.keys(result)); // top-level keys
        console.log(
          "Analysis keys:",
          result.analysis ? Object.keys(result.analysis) : "no analysis field"
        ); // analysis keys
        console.log("Full JSON:", JSON.stringify(result, null, 2)); // full structure
        setAnalysisResult(result.analysis);

        const ext = "." + file.name.split(".").pop().toLowerCase();
        if ([".log", ".txt"].includes(ext)) {
          const reader = new FileReader();
          reader.onload = (e) => setOriginalContent(e.target.result);
          reader.readAsText(file);
        } else {
          const content =
            result.original_content || // ✅ This will now work
            result.analysis?.masked_content ||
            null;

          if (content) {
            setOriginalContent(content);
          } else {
            setOriginalContent(`[No content extracted from ${file.name}]`);
          }
        }
      } catch (err) {
        const msg =
          err.response?.data?.detail ||
          err.message ||
          "File upload failed. Check backend connection.";
        setError(msg);
        setAnalysisResult(null);
      } finally {
        setLoading(false);
      }
    },
    [options]
  );

  const handleReset = () => {
    setAnalysisResult(null);
    setOriginalContent("");
    setError(null);
  };

  const tabs = [
    { id: "file", label: "📁 File Upload", icon: "📁" },
    { id: "text", label: "📝 Text Input", icon: "📝" },
    { id: "sql", label: "🗄️ SQL Query", icon: "🗄️" },
    { id: "chat", label: "💬 Live Chat", icon: "💬" },
  ];

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <div className="header-content">
          <div className="header-left">
            <h1>🔒 Security Pipeline</h1>
            <span className="header-subtitle">
              AI-Powered Security Analysis Engine
            </span>
          </div>
          <div className="header-right">
            <span
              className={`status-badge ${
                backendStatus?.status === "healthy"
                  ? "status-online"
                  : "status-offline"
              }`}
            >
              {backendStatus?.status === "healthy" ? "● Online" : "● Offline"}
            </span>
            {backendStatus?.modules?.ai_engine && (
              <span className="ai-badge">
                AI: {backendStatus.modules.ai_engine}
              </span>
            )}
          </div>
        </div>
      </header>

      <main className="app-main">
        {/* Options Bar */}
        <div className="options-bar">
          <label className="option-item">
            <input
              type="checkbox"
              checked={options.mask}
              onChange={(e) =>
                setOptions({ ...options, mask: e.target.checked })
              }
            />
            <span>🎭 Mask Sensitive Data</span>
          </label>
          <label className="option-item">
            <input
              type="checkbox"
              checked={options.blockHighRisk}
              onChange={(e) =>
                setOptions({ ...options, blockHighRisk: e.target.checked })
              }
            />
            <span>🚫 Block High Risk</span>
          </label>
          <label className="option-item">
            <input
              type="checkbox"
              checked={options.logAnalysis}
              onChange={(e) =>
                setOptions({ ...options, logAnalysis: e.target.checked })
              }
            />
            <span>📊 Log Analysis</span>
          </label>
          <label className="option-item">
            <input
              type="checkbox"
              checked={options.aiInsights}
              onChange={(e) =>
                setOptions({ ...options, aiInsights: e.target.checked })
              }
            />
            <span>🤖 AI Insights</span>
          </label>
          {analysisResult && (
            <button className="btn btn-reset" onClick={handleReset}>
              ↺ Reset
            </button>
          )}
        </div>

        {/* Input Section */}
        {!analysisResult && (
          <div className="input-section">
            <div className="tab-bar">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  className={`tab-btn ${
                    activeTab === tab.id ? "tab-active" : ""
                  }`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <div className="tab-content">
              {activeTab === "file" && (
                <FileUpload onUpload={handleFileUpload} loading={loading} />
              )}
              {activeTab === "text" && (
                <TextInput
                  inputType="text"
                  placeholder="Paste text content to analyze for security issues..."
                  onAnalyze={handleAnalyze}
                  loading={loading}
                />
              )}
              {activeTab === "sql" && (
                <TextInput
                  inputType="sql"
                  placeholder="Paste SQL queries to check for injection patterns, exposed credentials..."
                  onAnalyze={handleAnalyze}
                  loading={loading}
                />
              )}
              {activeTab === "chat" && (
                <TextInput
                  inputType="chat"
                  placeholder="Paste chat/conversation logs to scan for sensitive data leaks..."
                  onAnalyze={handleAnalyze}
                  loading={loading}
                />
              )}
            </div>
          </div>
        )}

        {/* Error Display */}
        {error && (
          <div className="error-banner">
            <span>⚠️ {error}</span>
            <button onClick={() => setError(null)}>✕</button>
          </div>
        )}

        {/* Loading Overlay */}
        {loading && (
          <div className="loading-overlay">
            <div className="loading-spinner"></div>
            <p>Analyzing content through security pipeline...</p>
          </div>
        )}

        {/* Results Section */}
        {analysisResult && !loading && (
          <div className="results-section">
            {/* Risk Summary Dashboard */}
            <RiskSummary result={analysisResult} />

            {/* Two-column layout: Log Viewer + Insights */}
            <div className="results-columns">
              <div className="results-left">
                <LogViewer
                  content={
                    options.mask && analysisResult.masked_content
                      ? analysisResult.masked_content
                      : originalContent
                  }
                  findings={analysisResult.findings}
                />
              </div>
              <div className="results-right">
                <InsightsPanel
                  insights={analysisResult.ai_insights}
                  findings={analysisResult.findings}
                />
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <p>
          Security Pipeline v1.0 • Processing time:{" "}
          {analysisResult ? `${analysisResult.processing_time_ms}ms` : "—"}
        </p>
      </footer>
    </div>
  );
}

export default App;
