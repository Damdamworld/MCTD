/**
 * Marketplace Scam Text Detector
 * Core logic: Regex + DFA only. No AI/ML model is used.
 *
 * Formal Language Mapping:
 * Σ = { N, C, P, U, O }
 * N = normal token
 * C = contact outside platform
 * P = external payment / account pattern
 * U = urgency or pressure
 * O = unrealistic offer / suspicious guarantee
 *
 * Q = { q0, q1, q2, q3 }
 * q0 = start state / safe
 * q3 = accepting state / high-risk scam alert
 */

export const TOKEN_MEANINGS = {
  N: 'Normal token',
  C: 'Contact outside official platform',
  P: 'External payment or private account pattern',
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
    explanation: 'Two warning signs were found. The text shows a stronger suspicious pattern.'
  },
  q3: {
    label: 'High Risk / Scam Alert',
    meaning: 'Three or more suspicious indicators detected',
    level: 3,
    className: 'high',
    explanation: 'Three or more warning signs were found. The DFA reaches q3, the accepting state for scam alert.'
  }
};

export const DFA_TRANSITIONS = {
  q0: { N: 'q0', C: 'q1', P: 'q1', U: 'q1', O: 'q1' },
  q1: { N: 'q1', C: 'q2', P: 'q2', U: 'q2', O: 'q2' },
  q2: { N: 'q2', C: 'q3', P: 'q3', U: 'q3', O: 'q3' },
  q3: { N: 'q3', C: 'q3', P: 'q3', U: 'q3', O: 'q3' }
};

export const REGEX_RULES = [
  {
    id: 'contact-outside-platform',
    symbol: 'C',
    category: 'Contact Outside Platform',
    weight: 1,
    description: 'The seller asks the buyer to move communication away from the official marketplace.',
    pattern: /\b(?:wa|w\.a|whatsapp|telegram|tg|dm|japri|chat pribadi|hubungi nomor|kontak saya|sms|telepon|call saya)\b/giu
  },
  {
    id: 'external-payment',
    symbol: 'P',
    category: 'External Payment',
    weight: 1,
    description: 'The message asks for payment outside the marketplace or uses private payment instructions.',
    pattern: /\b(?:transfer langsung|transfer aja|rekening pribadi|bayar di luar|bayar diluar|bayar langsung|dp dulu|dp aja|kirim dana|qris pribadi|dana|ovo|gopay|bank transfer|tf dulu)\b/giu
  },
  {
    id: 'private-bank-or-account-number',
    symbol: 'P',
    category: 'Private Account Number',
    weight: 1,
    description: 'The text contains a 10–16 digit number that may represent a private bank/account number.',
    pattern: /\b(?:\d[\s-]?){10,16}\b/gu
  },
  {
    id: 'urgency-pressure',
    symbol: 'U',
    category: 'Urgency or Pressure',
    weight: 1,
    description: 'The message creates pressure so the buyer acts quickly without checking properly.',
    pattern: /\b(?:cepat|sekarang juga|terakhir hari ini|stok tinggal satu|jangan lama|buruan|limited stock|today only|last chance|sebelum diambil orang|ambil sekarang)\b/giu
  },
  {
    id: 'unrealistic-offer-guarantee',
    symbol: 'O',
    category: 'Unrealistic Offer / Suspicious Guarantee',
    weight: 1,
    description: 'The offer or guarantee looks too strong, too cheap, or unusually certain.',
    pattern: /\b(?:murah banget|diskon besar|harga tidak masuk akal|promo rahasia|100% aman|100 persen aman|dijamin asli|anti tipu|pasti untung|too good to be true|harga miring|super murah)\b/giu
  },
  {
    id: 'outside-link',
    symbol: 'C',
    category: 'External Link',
    weight: 1,
    description: 'The message contains a link that may move the transaction outside the marketplace.',
    pattern: /(?:https?:\/\/|www\.)\S+|\b(?:bit\.ly|tinyurl\.com|s\.id|wa\.me)\/\S+/giu
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

export function buildAutomataInput(tokens, matches) {
  // The DFA only needs the suspicious symbols for the risk transition.
  // Normal tokens loop in the current state, so they are summarized rather than fully displayed.
  const suspiciousSymbols = matches.map((match) => match.symbol);
  return suspiciousSymbols.length > 0 ? suspiciousSymbols : tokens.map(() => 'N').slice(0, 1);
}

export function analyzeText(input) {
  const originalText = String(input || '');
  const normalizedText = normalizeText(originalText);
  const tokens = tokenize(originalText);
  const matches = detectPatterns(originalText);
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
