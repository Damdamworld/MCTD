import { analyzeText } from '../src/engine/analyzer.js';

export default function handler(request, response) {
  response.setHeader('Access-Control-Allow-Origin', '*');
  response.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  response.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (request.method === 'OPTIONS') {
    response.status(204).end();
    return;
  }

  if (request.method !== 'POST') {
    response.status(405).json({ error: 'Method not allowed. Use POST /api/analyze.' });
    return;
  }

  const text = typeof request.body?.text === 'string' ? request.body.text : '';

  if (!text.trim()) {
    response.status(400).json({ error: 'Text input is required.' });
    return;
  }

  const analysis = analyzeText(text);
  response.status(200).json({ analysis });
}
