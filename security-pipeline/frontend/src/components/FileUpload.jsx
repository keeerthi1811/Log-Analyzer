/**
 * File Upload Component with Drag & Drop
 * Supports .log, .txt, .pdf, .doc, .docx files
 */
import React, { useState, useRef, useCallback } from 'react';

const ALLOWED_EXTENSIONS = ['.log', '.txt', '.pdf', '.doc', '.docx'];
const MAX_SIZE_MB = 50;

const FileUpload = ({ onUpload, loading }) => {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewLines, setPreviewLines] = useState([]);
  const fileInputRef = useRef(null);

  const validateFile = (file) => {
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (!ALLOWED_EXTENSIONS.includes(ext)) {
      return `Unsupported file type: ${ext}. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`;
    }
    if (file.size > MAX_SIZE_MB * 1024 * 1024) {
      return `File too large: ${(file.size / 1024 / 1024).toFixed(1)}MB. Maximum: ${MAX_SIZE_MB}MB`;
    }
    return null;
  };

  const handleFile = useCallback((file) => {
    const error = validateFile(file);
    if (error) {
      alert(error);
      return;
    }
    setSelectedFile(file);

    // Generate preview for text files
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    if (['.log', '.txt'].includes(ext)) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const lines = e.target.result.split('\n').slice(0, 10);
        setPreviewLines(lines);
      };
      reader.readAsText(file);
    } else {
      setPreviewLines([`[Binary file: ${file.name} — ${(file.size / 1024).toFixed(1)}KB]`]);
    }
  }, []);

  // Drag & Drop handlers
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);

      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) {
        handleFile(files[0]);
      }
    },
    [handleFile]
  );

  const handleInputChange = (e) => {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  };

  const handleSubmit = () => {
    if (selectedFile && onUpload) {
      onUpload(selectedFile);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    setPreviewLines([]);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="file-upload-container">
      {/* Drop Zone */}
      <div
        className={`drop-zone ${isDragging ? 'drop-zone-active' : ''} ${
          selectedFile ? 'drop-zone-has-file' : ''
        }`}
        onDragEnter={handleDragEnter}
        onDragLeave={handleDragLeave}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept={ALLOWED_EXTENSIONS.join(',')}
          onChange={handleInputChange}
          className="file-input-hidden"
        />

        {!selectedFile ? (
          <div className="drop-zone-content">
            <div className="drop-icon">📂</div>
            <h3>Drop your file here</h3>
            <p>or click to browse</p>
            <p className="drop-hint">
              Supports: {ALLOWED_EXTENSIONS.join(', ')} (Max {MAX_SIZE_MB}MB)
            </p>
          </div>
        ) : (
          <div className="drop-zone-content">
            <div className="drop-icon">✅</div>
            <h3>{selectedFile.name}</h3>
            <p>{(selectedFile.size / 1024).toFixed(1)} KB</p>
          </div>
        )}
      </div>

      {/* File Preview */}
      {selectedFile && previewLines.length > 0 && (
        <div className="file-preview">
          <h4>📋 Preview (first 10 lines)</h4>
          <div className="preview-content">
            {previewLines.map((line, idx) => (
              <div key={idx} className="preview-line">
                <span className="preview-line-num">{idx + 1}</span>
                <span className="preview-line-text">{line}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Actions */}
      {selectedFile && (
        <div className="file-actions">
          <button
            className="btn btn-primary btn-lg"
            onClick={handleSubmit}
            disabled={loading}
          >
            {loading ? '⏳ Analyzing...' : '🔍 Analyze File'}
          </button>
          <button className="btn btn-secondary" onClick={handleClear} disabled={loading}>
            ✕ Clear
          </button>
        </div>
      )}
    </div>
  );
};

export default FileUpload;