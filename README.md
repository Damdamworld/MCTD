# Marketplace Scam Text Detector

A web-based Formal Language & Automata project that detects suspicious marketplace text using **Regular Expression** and **Deterministic Finite Automata (DFA)**.

No AI/ML model is used as the core logic. The detector is transparent: every result shows the matched Regex indicators, DFA input symbols, transition trace, final state, and risk explanation.

## Team

| Name | Student ID | Role |
|---|---:|---|
| Zevilia | 030202400014 | Frontend UI and user flow |
| Gesya Nabilla Estu Balqis | 03020240006 | Rule testing and documentation |
| Muhamad Nuralif Adam Laode | 030202400010 | Regex-DFA logic and integration |

## FLA Concept

### Alphabet

`Σ = { N, C, P, U, O }`

| Symbol | Meaning |
|---|---|
| `N` | Normal token |
| `C` | Contact outside official platform |
| `P` | External payment / private account pattern |
| `U` | Urgency or pressure |
| `O` | Unrealistic offer / suspicious guarantee |

### DFA States

| State | Meaning | Output |
|---|---|---|
| `q0` | No suspicious indicator | Safe |
| `q1` | One suspicious indicator | Low Risk |
| `q2` | Two suspicious indicators | Medium Risk |
| `q3` | Three or more suspicious indicators | High Risk / Scam Alert |

`q3` is the accepting state for scam alert.

### Transition Table

| Current State | Input `N` | Input `C/P/U/O` |
|---|---|---|
| `q0` | `q0` | `q1` |
| `q1` | `q1` | `q2` |
| `q2` | `q2` | `q3` |
| `q3` | `q3` | `q3` |

## Folder Structure

```txt
marketplace-scam-text-detector/
├─ api/
│  └─ analyze.js              # Vercel backend simulation endpoint
├─ src/
│  ├─ engine/
│  │  └─ analyzer.js          # Regex rules + DFA transition logic
│  ├─ main.js                 # Frontend interaction
│  └─ style.css               # UI design
├─ tests/
│  └─ analyzer.test.js        # Rule and DFA tests
├─ index.html
├─ package.json
└─ README.md
```

## Run Locally

```bash
npm install
npm run dev
```

Open the local Vite URL shown in the terminal.

For local testing with the API route:

```bash
npm install -g vercel
npm run dev:vercel
```

## Test the DFA Logic

```bash
npm test
```

## Build

```bash
npm run build
npm run preview
```

## Deploy to Vercel

### Option A — Vercel Dashboard

1. Push this project to GitHub.
2. Open Vercel and choose **Add New Project**.
3. Import the GitHub repository.
4. Use these settings:
   - Framework Preset: `Vite`
   - Build Command: `npm run build`
   - Output Directory: `dist`
5. Deploy.

### Option B — Vercel CLI

```bash
npm install -g vercel
vercel login
vercel --prod
```

## GitHub Push Commands

```bash
git init
git add .
git commit -m "feat: build regex dfa marketplace scam detector"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/marketplace-scam-text-detector.git
git push -u origin main
```

## Demo Script

1. Explain the problem: marketplace scams often appear in seller text, chat, or product descriptions.
2. Explain the method: Regex detects suspicious phrases, then each match becomes a DFA input symbol.
3. Show the DFA states: `q0`, `q1`, `q2`, `q3`.
4. Paste a safe message and show that the final state remains `q0`.
5. Paste a suspicious message and show how the transition reaches `q3`.
6. Point out that the result is explainable because the app shows matched patterns and transition trace.
