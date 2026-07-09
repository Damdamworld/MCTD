/**
 * Marketplace Scam Text Detector
 * Core logic: Regex + DFA only. No AI/ML model is used.
 *
 * Formal Language Mapping:
 * Σ = { N, C, P, U, O }
 * N = normal token
 * C = contact/link outside platform
 * P = external payment / private account / sensitive data pattern
 * U = urgency or pressure
 * O = unrealistic offer / suspicious guarantee
 *
 * Q = { q0, q1, q2, q3 }
 * q0 = start state / safe
 * q3 = accepting state / high-risk scam alert
 */

export const TOKEN_MEANINGS = {
  N: 'Normal token',
  C: 'Contact or link outside official platform',
  P: 'External payment, private account, or sensitive data pattern',
  U: 'Urgency or pressure',
  O: 'Unrealistic offer or suspicious guarantee'
};

export const STATES = {
  q0: {
    label: 'Safe',
    meaning: 'No suspicious indicator detected',
    level: 0,
    className: 'safe',
    explanation: 'The text does not match the suspicious marketplace patterns currently defined in the Regex rules.'
  },
  q1: {
    label: 'Low Risk',
    meaning: 'One suspicious indicator detected',
    level: 1,
    className: 'low',
    explanation: 'One warning sign was found. The message should be checked carefully before continuing.'
  },
  q2: {
    label: 'Medium Risk',
    meaning: 'Two suspicious indicators detected',
    level: 2,
    className: 'medium',
    explanation: 'Two different warning signs were found. The text shows a stronger suspicious pattern.'
  },
  q3: {
    label: 'High Risk / Scam Alert',
    meaning: 'Three or more suspicious indicators detected',
    level: 3,
    className: 'high',
    explanation: 'Three or more different warning signs were found. The DFA reaches q3, the accepting state for scam alert.'
  }
};

export const DFA_TRANSITIONS = {
  q0: { N: 'q0', C: 'q1', P: 'q1', U: 'q1', O: 'q1' },
  q1: { N: 'q1', C: 'q2', P: 'q2', U: 'q2', O: 'q2' },
  q2: { N: 'q2', C: 'q3', P: 'q3', U: 'q3', O: 'q3' },
  q3: { N: 'q3', C: 'q3', P: 'q3', U: 'q3', O: 'q3' }
};

/**
 * The rules are grouped into the same DFA alphabet from the proposal.
 * More keywords are added in Indonesian and English, but the formal model stays simple:
 * Regex detects lexical patterns -> pattern becomes C/P/U/O symbol -> DFA classifies final state.
 */
export const REGEX_RULES = [
  {
    id: 'contact-outside-platform',
    signalKey: 'C_CONTACT',
    symbol: 'C',
    category: 'Contact Outside Platform',
    weight: 1,
    description: 'The seller asks the buyer to move communication away from the official marketplace chat.',
    pattern: /\b(?:wa|w\.?a|whatsapp|telegram|tg|line|dm|inbox|japri|sms|telepon|telpon|call me|text me|chat me)\b|\b(?:chat pribadi|private chat|chat personal|hubungi nomor|kontak saya|nomor saya|lanjut(?:kan)? (?:di|ke) (?:wa|whatsapp|telegram|dm)|luar aplikasi|outside (?:the )?(?:app|platform)|off[-\s]?platform|jangan chat di (?:aplikasi|app)|chat di luar)\b/giu
  },
  {
    id: 'external-link',
    signalKey: 'C_LINK',
    symbol: 'C',
    category: 'External Link',
    weight: 1,
    description: 'The text contains a link that may redirect the buyer outside the official marketplace.',
    pattern: /(?:https?:\/\/|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|s\.id|wa\.me|t\.me|linktr\.ee)\/\S+/giu
  },
  {
    id: 'external-payment',
    signalKey: 'P_PAYMENT',
    symbol: 'P',
    category: 'External Payment',
    weight: 1,
    description: 'The message asks for payment outside checkout, escrow, or official marketplace payment flow.',
    pattern: /\b(?:transfer langsung|langsung transfer|transfer aja|tf dulu|tf aja|rekening pribadi|rek pribadi|bayar di luar|bayar diluar|bayar langsung|bayar manual|dp dulu|dp aja|uang muka|booking fee|deposit first|kirim dana|send money|direct payment|pay outside|outside payment|private account|bank transfer|wire transfer|qris pribadi|via qris|via dana|via ovo|via gopay|via shopeepay|e-wallet pribadi|tanpa checkout|jangan checkout|skip checkout|no checkout|tidak perlu checkout)\b/giu
  },
  {
    id: 'private-bank-or-account-number',
    signalKey: 'P_NUMBER',
    symbol: 'P',
    category: 'Private Account / Phone Number',
    weight: 1,
    description: 'The text contains a 10–16 digit number that may represent a bank account, phone, or wallet number.',
    pattern: /\b(?:\d[\s-]?){10,16}\b/gu
  },
  {
    id: 'extra-fee-before-transaction',
    signalKey: 'P_EXTRA_FEE',
    symbol: 'P',
    category: 'Extra Fee Before Transaction',
    weight: 1,
    description: 'The seller asks for an extra fee before the official marketplace transaction is completed.',
    pattern: /\b(?:biaya admin dulu|biaya ongkir dulu|ongkir dulu|biaya kirim dulu|biaya pengiriman dulu|biaya verifikasi|biaya asuransi|asuransi tambahan|pajak dulu|custom fee|insurance fee|shipping fee first|admin fee first)\b/giu
  },
  {
    id: 'sensitive-data-request',
    signalKey: 'P_SENSITIVE_DATA',
    symbol: 'P',
    category: 'Sensitive Data Request',
    weight: 1,
    description: 'The message asks for private data that should not be shared in a marketplace transaction.',
    pattern: /\b(?:kode otp|otp|password|kata sandi|pin|kode verifikasi|verification code|login akun|minta data|data ktp|foto ktp|nomor kartu|card number|cvv)\b/giu
  },
  {
    id: 'urgency-pressure',
    signalKey: 'U_URGENCY',
    symbol: 'U',
    category: 'Urgency or Pressure',
    weight: 1,
    description: 'The message creates pressure so the buyer acts quickly without checking properly.',
    pattern: /\b(?:cepat|segera|sekarang juga|harus sekarang|deal sekarang|terakhir hari ini|hari ini saja|stok tinggal (?:satu|1|sedikit)|stok terbatas|sisa (?:satu|1)|jangan lama|jangan pikir lama|buruan|buru|limited stock|today only|last chance|only one left|before sold out|sebelum diambil orang|ambil sekarang|first come first serve|fcfs|waktu terbatas)\b/giu
  },
  {
    id: 'unrealistic-price-or-offer',
    signalKey: 'O_PRICE',
    symbol: 'O',
    category: 'Unrealistic Price or Offer',
    weight: 1,
    description: 'The price or promotion looks too cheap, secret, or unreasonable compared with normal marketplace offers.',
    pattern: /\b(?:murah banget|super murah|harga miring|harga tidak masuk akal|harga ga masuk akal|dibawah harga pasar|di bawah harga pasar|below market price|diskon besar|promo rahasia|promo khusus rahasia|too good to be true|cuci gudang besar-besaran|harga spesial hari ini)\b/giu
  },
  {
    id: 'suspicious-guarantee',
    signalKey: 'O_GUARANTEE',
    symbol: 'O',
    category: 'Suspicious Guarantee',
    weight: 1,
    description: 'The message uses exaggerated guarantees that are commonly used to build false trust.',
    pattern: /\b(?:100% aman|100 persen aman|dijamin asli|dijamin ori|anti tipu|no tipu|pasti untung|guaranteed profit|no risk|risk free|uang kembali 100|garansi uang kembali|amanah 100|trusted 100)\b/giu
  }
];

export const INDICATOR_GUIDE = [
  {
    symbol: 'C',
    title: 'Contact Outside Platform',
    indicator: 'Seller asks to move chat to WhatsApp, Telegram, DM, private chat, phone, or external link.',
    examples: ['lanjut WA', 'hubungi nomor saya', 'chat di luar aplikasi', 'wa.me/...']
  },
  {
    symbol: 'P',
    title: 'External Payment / Private Account',
    indicator: 'Seller asks for transfer, DP, private account, e-wallet, extra fee, or skips official checkout.',
    examples: ['transfer langsung', 'DP dulu', 'rekening pribadi', 'jangan checkout']
  },
  {
    symbol: 'P',
    title: 'Sensitive Data Request',
    indicator: 'Seller asks for OTP, password, PIN, verification code, ID card, card number, or CVV.',
    examples: ['kirim kode OTP', 'minta password', 'foto KTP', 'CVV']
  },
  {
    symbol: 'U',
    title: 'Urgency or Pressure',
    indicator: 'Seller pushes buyer to act immediately and not check the transaction carefully.',
    examples: ['stok tinggal satu', 'hari ini saja', 'buruan', 'last chance']
  },
  {
    symbol: 'O',
    title: 'Unrealistic Offer / Guarantee',
    indicator: 'Offer looks too cheap or guarantee sounds exaggerated and too certain.',
    examples: ['murah banget', 'too good to be true', '100% aman', 'pasti untung']
  }
];

const NORMALIZE_SYMBOLS_REGEX = /[^\p{L}\p{N}%:/._\-\s]/gu;

export function normalizeText(input) {
  return String(input || '')
    .toLowerCase()
    .normalize('NFKC')
    .replace(NORMALIZE_SYMBOLS_REGEX, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function tokenize(text) {
  const normalized = normalizeText(text);
  if (!normalized) return [];
  return normalized.split(/\s+/).filter(Boolean);
}

function cloneRegex(regex) {
  return new RegExp(regex.source, regex.flags);
}

export function detectPatterns(input) {
  const normalized = normalizeText(input);
  const matches = [];

  for (const rule of REGEX_RULES) {
    const regex = cloneRegex(rule.pattern);
    for (const match of normalized.matchAll(regex)) {
      const value = match[0].trim();
      if (!value) continue;
      matches.push({
        ruleId: rule.id,
        signalKey: rule.signalKey,
        symbol: rule.symbol,
        category: rule.category,
        description: rule.description,
        value,
        index: match.index ?? -1,
        endIndex: (match.index ?? 0) + value.length,
        weight: rule.weight
      });
    }
  }

  return matches.sort((a, b) => a.index - b.index || a.value.localeCompare(b.value));
}

export function runDFA(symbols) {
  let currentState = 'q0';
  const trace = [];

  for (const symbol of symbols) {
    const inputSymbol = DFA_TRANSITIONS[currentState][symbol] ? symbol : 'N';
    const nextState = DFA_TRANSITIONS[currentState][inputSymbol];
    trace.push({
      from: currentState,
      input: inputSymbol,
      to: nextState
    });
    currentState = nextState;
  }

  return {
    finalState: currentState,
    trace,
    accepted: currentState === 'q3'
  };
}

export function buildRiskSignals(matches) {
  const seen = new Set();
  const signals = [];

  for (const match of matches) {
    if (seen.has(match.signalKey)) continue;
    seen.add(match.signalKey);
    signals.push({
      signalKey: match.signalKey,
      symbol: match.symbol,
      category: match.category,
      firstMatch: match.value,
      description: match.description,
      index: match.index
    });
  }

  return signals.sort((a, b) => a.index - b.index);
}

export function buildAutomataInput(tokens, matches) {
  // DFA state changes use distinct warning signals, not repeated words from the same signal.
  // This keeps the classification more fair: one repeated phone number does not become High Risk by itself.
  const riskSignals = buildRiskSignals(matches);
  const suspiciousSymbols = riskSignals.map((signal) => signal.symbol);
  return suspiciousSymbols.length > 0 ? suspiciousSymbols : tokens.map(() => 'N').slice(0, 1);
}

export function analyzeText(input) {
  const originalText = String(input || '');
  const normalizedText = normalizeText(originalText);
  const tokens = tokenize(originalText);
  const matches = detectPatterns(originalText);
  const riskSignals = buildRiskSignals(matches);
  const automataInput = buildAutomataInput(tokens, matches);
  const dfa = runDFA(automataInput);
  const stateInfo = STATES[dfa.finalState];

  const uniqueCategories = [...new Set(matches.map((match) => match.category))];
  const transitionPath = dfa.trace.length
    ? ['q0', ...dfa.trace.map((step) => `${step.input}→${step.to}`)].join('  ')
    : 'q0';

  return {
    originalText,
    normalizedText,
    tokenCount: tokens.length,
    tokens,
    matches,
    riskSignals,
    uniqueCategories,
    automataInput,
    dfa,
    transitionPath,
    result: {
      state: dfa.finalState,
      label: stateInfo.label,
      meaning: stateInfo.meaning,
      level: stateInfo.level,
      className: stateInfo.className,
      explanation: stateInfo.explanation,
      isScamAlert: dfa.accepted
    }
  };
}
