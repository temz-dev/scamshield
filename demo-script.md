# ScamShield — demo video narration script

Video: 1920x1080, 30fps, MP4. Calm male voiceover ("Measured Sundial", avocado_v2:qvd_00325), burned-in captions. Target length ~3:00–3:10.

## S1 — Hook (0:00–0:20, ~20s)
Crypto scams steal billions every year. And the most common ones are not clever hacks. They are messages. A DM promising to double your ETH. A link that looks exactly like your exchange. One click, one send, and the money is gone for good.

## S2 — The solution (0:20–0:50, ~30s)
Meet ScamShield. You paste anything suspicious — a message, a link, or a token address — and it gives you a verdict, with the reasons spelled out. No account, no upload. The check runs right in your browser. Let me show you what it does with three real examples.

## S3a — Live demo: the giveaway DM (0:50–1:25, ~35s)
First, the classic: a DM claiming to be an Elon Musk giveaway. Send half an ETH, get one back. Paste it in, hit analyze. Likely Scam — ninety-five out of a hundred. And look at why: a double-your-money promise, a giveaway claim, impersonation of a known figure, urgency language, and an instruction to send crypto to an address. Five flags, each with its weight shown. That is the whole point — you can see exactly why it scored what it did.

## S3b — Live demo: the fake link (1:25–1:55, ~30s)
Next, a link. "Verify your Binance account now, or your funds will be frozen." The address is binance-secure-login.com. It looks right — but it is not binance.com. ScamShield catches the lookalike domain, the fake verification lure, and the urgency trick. Likely Scam, seventy-five out of a hundred. One letter is all it takes, and this is the check most people skip.

## S3c — Live demo: the legit chat (1:55–2:20, ~25s)
Now the other side. A normal market chat — Bitcoin's price, moving some SOL to a hardware wallet. Safe, nine out of a hundred. And notice this: the message mentions a seed phrase, but it is advice to keep it offline — a warning, not a scam. ScamShield spots the difference, so honest advice does not get flagged.

## S4 — How it works (2:20–2:50, ~30s)
How does it work? A transparent scoring engine. Thirteen text patterns, six link checks, and token checks — with live data from DexScreener when a token address is available. Every flag has a weight, and the score is just the sum, capped at one hundred. The same input always gives the same answer. And to be clear: this is a deterministic pattern engine, not a live language model. No black box, no mystery score.

## S5 — Close (2:50–3:10, ~20s)
ScamShield is for anyone who has ever paused before sending crypto and wondered, "is this real?" Paste it first. Check before you send. Try it — and if it saves you once, it has already done its job.

---

## Verified facts used in the narration (from the live engine, 2026-11-25)
- Giveaway DM sample → Likely Scam, 95/100. Flags: "Send X, get 2X back" promise +30; Giveaway claim +20; Impersonation +20; Urgency +10; Instruction to send crypto to an address +15.
- Fake Binance link sample → Likely Scam, 75/100. Flags: "Verify your wallet" lure +25; Urgency +10; Lookalike domain of binance +40.
- Legit market chat sample → Safe, 9/100. One dampened flag (seed-phrase mention, weight reduced by the educational-context dampener) plus an "Educational context detected" note.
- Engine: 13 text patterns (TEXT_CHECKS), 6 link checks (raw IP, punycode, shortener, suspicious TLD, plain HTTP, lookalike domain), token checks with optional live DexScreener lookup. Score = sum of weights, capped at 100. Bands: 0–24 Safe, 25–49 Caution, 50–74 High Risk, 75–100 Likely Scam. Deterministic, not a live LLM.
