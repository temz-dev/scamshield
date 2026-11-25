# ScamShield — Crypto Scam Detector

**SLAY HACKS 2026 entry (solo, first-time hackathon participant).**

## The problem

Crypto scams steal billions every year, and the most common ones are not
sophisticated hacks — they are messages. A DM promising to double your ETH,
a "verify your wallet" page that is one letter away from the real exchange,
a brand-new token with no liquidity. Most victims lose money not because the
scam was clever, but because nobody checked before they sent.

## What it does

Paste a crypto message, a link, or a token address. ScamShield returns:

- A **verdict** — Safe / Caution / High Risk / Likely Scam
- A **risk score (0–100)** with a visual meter
- **Every red flag found**, each with a plain-English explanation of why it
  matters and the weight it contributed to the score
- **What to do next** — tailored to the verdict

Three one-click samples are built in: a giveaway DM, a fake exchange link,
and a legit market chat (which also demonstrates the educational-context
handling — safe advice that quotes scam terms is not flagged as a scam).

## How the analysis engine works

Honest answer: this is a **deterministic pattern-and-heuristics engine**,
not a live language model. The same input always gives the same score, and
every point of the score can be traced to a named check. The engine
(`engine.js`, shared by the app and the test suite) runs 20+ checks in three
groups:

**Message patterns** — doubling promises ("send 0.5 ETH, get 1 ETH back",
including the numeric form), guaranteed returns, "risk-free" profit claims,
seed-phrase / private-key requests, "verify your wallet" lures, giveaway and
airdrop claims, impersonation of known figures and brands, urgency/pressure
language, unrealistic yields (500% APY, "10x guaranteed"), DM solicitation,
and instructions to send crypto to an address.

**Link checks** — lookalike / typo-squat domains of 19 known brands
(Levenshtein distance + substring + subdomain tricks), punycode (`xn--`)
homograph domains, URL shorteners, raw-IP URLs, suspicious TLDs, and plain
HTTP.

**Token checks** — address-format validation (Ethereum `0x…` and Solana
base58), plus an optional live lookup against the **keyless public
DexScreener API** for pair and liquidity data: no trading data, very low
liquidity, and pairs created less than 24 hours ago are all flagged. If the
lookup is unreachable, the app says so in the UI and the local analysis
stands on its own — nothing breaks.

**Scoring.** Each flag carries a weight (5–40). The score is the sum,
capped at 100. Bands: 0–24 Safe, 25–49 Caution, 50–74 High Risk, 75–100
Likely Scam. One safeguard: an **educational dampener**. If the text is
clearly a warning or explainer ("how to spot", "beware", "never send"),
text-pattern weights are multiplied by 0.25, so scam terms quoted in an
explainer do not flag the explainer itself. URL and token checks are never
dampened — a malicious link is malicious even inside a warning.

**Where an LLM would plug in.** The engine is deliberately layered: the
deterministic checks are the fast, explainable first pass. An LLM layer
would sit on top as a second opinion — given the input text plus the flags
already found, it could catch novel phrasings the patterns miss and explain
borderline cases in natural language, with its verdict merged as an extra
weighted flag. That layer is designed but not live in this prototype: it
needs an API key, and none is bundled or claimed.

## How to run it

No build step, no server required. Two steps:

```bash
cd slay-hacks-scam-detector
python3 -m http.server 8000
```

Then open http://localhost:8000 in a browser. (Opening `index.html`
directly from disk also works — the app only needs HTTP for the optional
DexScreener fetch.)

## Tests

```bash
node tests/test_engine.js   # 19 unit cases — scam, legit, edge cases, token enrichment
node tests/e2e.js           # Playwright end-to-end in headless Chromium + screenshots
```

Unit tests cover: scam messages (must flag), legit messages and real
exchange URLs (must pass), tricky cases (an educational explainer quoting
scam terms; safe seed-phrase advice; a warning that still contains a
malicious link), and the token-enrichment logic with mocked DexScreener
data. The e2e test loads the app in a real browser, clicks all three
samples, verifies the verdicts, and captures the screenshots in
`screenshots/` — with zero console or page errors (a failed DexScreener
request in a sandboxed browser is the designed offline fallback, not an
error).

## File layout

```
index.html          Page structure (hero, analyzer, results, how-it-works, red flags)
styles.css          Dark security-product styling, responsive
app.js              UI wiring, DexScreener lookup, sample data, report copy
engine.js           Analysis engine (browser + Node, same code, fully tested)
tests/
  test_engine.js    Unit tests (node tests/test_engine.js)
  e2e.js            Playwright end-to-end + screenshots (node tests/e2e.js)
screenshots/
  01-landing.png    Landing / input state
  02-high-risk.png  "Likely Scam" result (Elon giveaway DM)
  03-safe.png       "Safe" result (legit market chat)
  04-token.png      Token-address result
package.json        Dev tooling only (playwright-core for the e2e test)
```

## What is NOT in here

No API keys, no accounts, no server, no tracking, no data collection.
Nothing you paste leaves your browser except an optional public lookup of
a token address on DexScreener. ScamShield is an educational prototype,
not financial advice — a "Safe" verdict means "no red flags found", not
"guaranteed legitimate". Always verify through official channels before
sending funds.
