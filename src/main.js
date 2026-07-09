import './style.css';
import { analyzeText, DFA_TRANSITIONS, REGEX_RULES, STATES, TOKEN_MEANINGS } from './engine/analyzer.js';

const examples = [
  {
    label: 'High Risk',
    text: 'Barang masih ada. Kalau mau cepat hubungi WhatsApp saya dan transfer DP dulu ke rekening pribadi 123456789012.'
  },
  {
    label: 'Safe',
    text: 'Produk original, pembayaran melalui aplikasi marketplace, bisa checkout langsung. Garansi mengikuti ketentuan platform.'
  },
  {
    label: 'Medium Risk',
    text: 'Stok tinggal satu, tapi pembayaran tetap checkout lewat aplikasi marketplace ya.'
  },
  {
    label: 'High Risk',
    text: 'Harga murah banget, promo rahasia hari ini. Chat WA saya sekarang juga, bayar langsung saja biar cepat.'
  }
];

const app = document.querySelector('#app');

app.innerHTML = `
  <main class="page-shell">
    <section class="hero">
      <div class="hero-copy">
        <p class="eyebrow">Formal Language & Automata Project</p>
        <h1>Marketplace Scam Text Detector</h1>
        <p class="subtitle">A transparent rule-based detector using <strong>Regular Expression</strong> and <strong>DFA</strong>. No AI/ML prediction is used as the core logic.</p>
        <div class="hero-actions">
          <a class="button button-secondary" href="#detector">Try Detector</a>
          <a class="button button-ghost" href="#automata">View DFA Model</a>
        </div>
      </div>
      <div class="hero-card" aria-label="DFA state summary">
        <span class="state-pill safe">q0 Safe</span>
        <span class="arrow">→</span>
        <span class="state-pill low">q1 Low</span>
        <span class="arrow">→</span>
        <span class="state-pill medium">q2 Medium</span>
        <span class="arrow">→</span>
        <span class="state-pill high">q3 High</span>
        <p>Each suspicious token moves the automaton to a higher risk state.</p>
      </div>
    </section>

    <section id="detector" class="detector-grid">
      <article class="panel input-panel">
        <div class="panel-header">
          <p class="eyebrow">Input</p>
          <h2>Paste Marketplace Text</h2>
        </div>
        <textarea id="textInput" placeholder="Example: Barang masih ada. Kalau mau cepat hubungi WhatsApp saya dan transfer DP dulu..."></textarea>
        <div class="button-row">
          <button id="analyzeButton" class="button">Analyze Text</button>
          <button id="resetButton" class="button button-secondary">Reset</button>
        </div>
        <div class="examples" aria-label="sample texts">
          <p>Sample test cases:</p>
          <div id="exampleButtons" class="example-buttons"></div>
        </div>
      </article>

      <article class="panel result-panel" aria-live="polite">
        <div class="panel-header">
          <p class="eyebrow">Output</p>
          <h2>Risk Classification</h2>
        </div>
        <div id="emptyState" class="empty-state">Enter a marketplace message, then click Analyze Text.</div>
        <div id="resultContent" class="result-content hidden"></div>
      </article>
    </section>

    <section class="panel explanation-panel">
      <div class="panel-header">
        <p class="eyebrow">Highlighted Text</p>
        <h2>Suspicious Terms Found</h2>
      </div>
      <div id="highlightedText" class="highlighted-text">No text analyzed yet.</div>
    </section>

    <section id="automata" class="info-grid">
      <article class="panel">
        <div class="panel-header">
          <p class="eyebrow">Regex</p>
          <h2>Rule Categories</h2>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Symbol</th><th>Category</th><th>Pattern Example</th></tr>
            </thead>
            <tbody>
              ${REGEX_RULES.map((rule) => `<tr><td><code>${rule.symbol}</code></td><td>${rule.category}</td><td><code>${escapeHtml(shortenRegex(rule.pattern.source))}</code></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
      </article>

      <article class="panel">
        <div class="panel-header">
          <p class="eyebrow">DFA</p>
          <h2>Transition Table</h2>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>State</th><th>N</th><th>C/P/U/O</th><th>Risk</th></tr>
            </thead>
            <tbody>
              ${Object.entries(DFA_TRANSITIONS).map(([state, transitions]) => `<tr><td><code>${state}</code></td><td>${transitions.N}</td><td>${transitions.C}</td><td>${STATES[state].label}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        <div class="alphabet-list">
          ${Object.entries(TOKEN_MEANINGS).map(([symbol, meaning]) => `<span><code>${symbol}</code> ${meaning}</span>`).join('')}
        </div>
      </article>
    </section>

    <footer>
      <p>Built for Formal Language & Automata. Core method: Regex → Token Category → DFA Transition → Risk Result.</p>
    </footer>
  </main>
`;

const textInput = document.querySelector('#textInput');
const analyzeButton = document.querySelector('#analyzeButton');
const resetButton = document.querySelector('#resetButton');
const resultContent = document.querySelector('#resultContent');
const emptyState = document.querySelector('#emptyState');
const highlightedText = document.querySelector('#highlightedText');
const exampleButtons = document.querySelector('#exampleButtons');

examples.forEach((example) => {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'chip-button';
  button.textContent = example.label;
  button.addEventListener('click', () => {
    textInput.value = example.text;
    analyzeCurrentText();
  });
  exampleButtons.appendChild(button);
});

analyzeButton.addEventListener('click', analyzeCurrentText);
resetButton.addEventListener('click', () => {
  textInput.value = '';
  resultContent.classList.add('hidden');
  emptyState.classList.remove('hidden');
  highlightedText.textContent = 'No text analyzed yet.';
});

textInput.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
    analyzeCurrentText();
  }
});

async function analyzeCurrentText() {
  const text = textInput.value.trim();
  if (!text) {
    resultContent.classList.add('hidden');
    emptyState.classList.remove('hidden');
    highlightedText.textContent = 'Please enter text first.';
    return;
  }

  const analysis = await analyzeWithApiFallback(text);
  renderResult(analysis);
  renderHighlight(text, analysis.matches);
}

async function analyzeWithApiFallback(text) {
  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    if (!response.ok) throw new Error('API request failed');
    const payload = await response.json();
    if (!payload?.analysis) throw new Error('Invalid API response');
    return payload.analysis;
  } catch (error) {
    // Local fallback keeps the demo working even when Vite is run without Vercel Functions.
    return analyzeText(text);
  }
}

function renderResult(analysis) {
  const { result, matches, tokenCount, automataInput, dfa, transitionPath } = analysis;
  emptyState.classList.add('hidden');
  resultContent.classList.remove('hidden');

  resultContent.innerHTML = `
    <div class="risk-card ${result.className}">
      <p class="risk-state">Final State: <strong>${result.state}</strong></p>
      <h3>${result.label}</h3>
      <p>${result.explanation}</p>
    </div>

    <div class="metric-grid">
      <div><span>${tokenCount}</span><p>Tokens</p></div>
      <div><span>${matches.length}</span><p>Suspicious Matches</p></div>
      <div><span>${automataInput.join(' ') || 'N'}</span><p>DFA Input</p></div>
    </div>

    <div class="detail-block">
      <h4>DFA Transition Path</h4>
      <code>${escapeHtml(transitionPath)}</code>
    </div>

    <div class="detail-block">
      <h4>Detected Indicators</h4>
      ${matches.length ? `<ul class="match-list">${matches.map((match) => `
        <li>
          <span class="symbol">${match.symbol}</span>
          <div>
            <strong>${match.category}</strong>
            <p>Matched: <code>${escapeHtml(match.value)}</code></p>
            <small>${match.description}</small>
          </div>
        </li>
      `).join('')}</ul>` : '<p>No suspicious indicator found by the current Regex rules.</p>'}
    </div>

    <div class="detail-block">
      <h4>Transition Trace</h4>
      ${dfa.trace.length ? `<ol class="trace-list">${dfa.trace.map((step) => `<li><code>${step.from}</code> + <code>${step.input}</code> → <code>${step.to}</code></li>`).join('')}</ol>` : '<p>No transition recorded.</p>'}
    </div>
  `;
}

function renderHighlight(text, matches) {
  if (!matches.length) {
    highlightedText.textContent = text;
    return;
  }

  const normalized = text.toLowerCase().normalize('NFKC');
  const ranges = [];

  for (const match of matches) {
    const needle = match.value.toLowerCase().normalize('NFKC');
    let start = normalized.indexOf(needle);
    while (start !== -1) {
      ranges.push({ start, end: start + needle.length, symbol: match.symbol, category: match.category });
      start = normalized.indexOf(needle, start + needle.length);
    }
  }

  const merged = mergeRanges(ranges).sort((a, b) => a.start - b.start);
  let cursor = 0;
  let html = '';

  for (const range of merged) {
    html += escapeHtml(text.slice(cursor, range.start));
    html += `<mark title="${escapeHtml(range.category)}">${escapeHtml(text.slice(range.start, range.end))}<sup>${range.symbol}</sup></mark>`;
    cursor = range.end;
  }
  html += escapeHtml(text.slice(cursor));
  highlightedText.innerHTML = html;
}

function mergeRanges(ranges) {
  const sorted = ranges.sort((a, b) => a.start - b.start || b.end - a.end);
  const merged = [];
  for (const range of sorted) {
    const last = merged[merged.length - 1];
    if (!last || range.start > last.end) {
      merged.push({ ...range });
    } else if (range.end > last.end) {
      last.end = range.end;
      last.symbol = `${last.symbol}/${range.symbol}`;
    }
  }
  return merged;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function shortenRegex(source) {
  return source.length > 80 ? `${source.slice(0, 80)}…` : source;
}
