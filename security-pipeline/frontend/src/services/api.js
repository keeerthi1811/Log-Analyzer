/**
 * API Service Layer
 * Handles all communication with the FastAPI backend.
 */
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000/api';

const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 120000, // 2 min timeout for large file analysis
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Analyze text/log/SQL/chat content via JSON payload.
 */
export const analyzeContent = async (inputType, content, options = {}) => {
  const payload = {
    input_type: inputType,
    content: content,
    options: {
      mask: options.mask || false,
      block_high_risk: options.blockHighRisk || false,
      log_analysis: options.logAnalysis !== undefined ? options.logAnalysis : true,
      ai_insights: options.aiInsights !== undefined ? options.aiInsights : true,
      chunk_size: options.chunkSize || 500,
    },
  };

  const response = await apiClient.post('/analyze', payload);
  return response.data;
};

/**
 * Upload and analyze a file (PDF, DOC, TXT, LOG).
 */
export const uploadFile = async (file, options = {}) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('mask', options.mask || false);
  formData.append('block_high_risk', options.blockHighRisk || false);
  formData.append('log_analysis', options.logAnalysis !== undefined ? options.logAnalysis : true);
  formData.append('ai_insights', options.aiInsights !== undefined ? options.aiInsights : true);
  formData.append('chunk_size', options.chunkSize || 500);

  const response = await apiClient.post('/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

/**
 * Health check.
 */
export const healthCheck = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export default apiClient;