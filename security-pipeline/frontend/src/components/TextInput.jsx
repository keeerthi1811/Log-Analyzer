/**
 * Text/SQL/Chat Input Component
 * Provides a textarea for pasting content with sample data options.
 */
import React, { useState } from 'react';

const SAMPLES = {
  text: `Server config file:
database_url=postgres://admin:p@ssw0rd@db.prod.internal:5432/main
api_key = sk-proj-abc123def456ghi789jkl012
Contact support at admin@company.com or call 555-123-4567
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,

  sql: `-- User authentication query
SELECT * FROM users WHERE username = 'admin' AND password = 'admin123';
INSERT INTO api_keys (key, user_id) VALUES ('sk-live-abc123xyz789', 42);
-- Connection: mysql://root:rootpass@192.168.1.100:3306/production`,

  chat: `[10:23] User: Hey, can you reset my password?
[10:24] Agent: Sure, I've set it to TempPass#2024
[10:25] User: My email is john.doe@company.com
[10:26] Agent: I see your API key is sk-user-xyz789abc123 — please don't share this
[10:27] User: My SSN is 123-45-6789 for verification`,
};

const TextInput = ({ inputType, placeholder, onAnalyze, loading }) => {
  const [content, setContent] = useState('');

  const handleSubmit = () => {
    if (content.trim() && onAnalyze) {
      onAnalyze(inputType, content);
    }
  };

  const handleLoadSample = () => {
    setContent(SAMPLES[inputType] || SAMPLES.text);
  };

  const lineCount = content.split('\n').length;

  return (
    <div className="text-input-container">
      <div className="text-input-header">
        <span className="line-count">
          {lineCount} line{lineCount !== 1 ? 's' : ''} • {content.length} chars
        </span>
        <button className="btn btn-ghost" onClick={handleLoadSample}>
          📋 Load Sample
        </button>
      </div>

      <div className="text-editor">
        <div className="line-numbers">
          {content.split('\n').map((_, idx) => (
            <div key={idx} className="editor-line-num">
              {idx + 1}
            </div>
          ))}
        </div>
        <textarea
          className="text-area"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder={placeholder}
          spellCheck={false}
        />
      </div>

      <div className="text-actions">
        <button
          className="btn btn-primary btn-lg"
          onClick={handleSubmit}
          disabled={!content.trim() || loading}
        >
          {loading ? '⏳ Analyzing...' : '🔍 Analyze Content'}
        </button>
        <button
          className="btn btn-secondary"
          onClick={() => setContent('')}
          disabled={loading}
        >
          ✕ Clear
        </button>
      </div>
    </div>
  );
};

export default TextInput;