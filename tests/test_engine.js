/**
 * ScamShield engine unit tests.
 * Run:  node tests/test_engine.js
 * Exits 0 when every case passes, 1 otherwise.
 */
const engine = require('../engine.js');

let passed = 0;
let failed = 0;

function check(name, fn) {
  try {
    fn();
    passed++;
    console.log('  PASS  ' + name);
  } catch (e) {
    failed++;
    console.log('  FAIL  ' + name + ' — ' + e.message);
  }
}

function eq(actual, expected, what) {
  if (actual !== expected) throw new Error(what + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
}

function hasFlag(result, id) {
  if (!result.flags.some(f => f.id === id)) {
    throw new Error('expected flag "' + id + '", got [' + result.flags.map(f => f.id).join(', ') + ']');
  }
}

function noFlag(result, id) {
  if (result.flags.some(f => f.id === id)) {
    throw new Error('did not expect flag "' + id + '"');
  }
}

console.log('ScamShield engine tests\n--- scam messages (must flag) ---');

// 1. Classic Elon doubling giveaway — must be Likely Scam.
check('Elon doubling giveaway → Likely Scam', () => {
  const r = engine.analyze('🚀 ELON MUSK GIVEAWAY! Send 0.5 ETH to 0x7f3a9c2e1b4d8f6a0c5e9b2d4f6a8c0e1b3d5f7 and receive 1 ETH back! Limited time, act now before it ends!');
  eq(r.verdict.id, 'scam', 'verdict');
  if (r.score < 75) throw new Error('score too low: ' + r.score);
  hasFlag(r, 'doubling');
  hasFlag(r, 'giveaway');
  hasFlag(r, 'impersonation');
});

// 2. Seed-phrase phishing — High Risk.
check('Seed phrase phishing → High Risk', () => {
  const r = engine.analyze('Your wallet needs verification — enter your seed phrase here to verify your wallet and restore access.');
  eq(r.verdict.id, 'high', 'verdict');
  hasFlag(r, 'seed-phrase');
  hasFlag(r, 'verify-wallet');
});

// 3. Guaranteed returns + DM solicitation — Likely Scam.
check('Guaranteed 500% APY + DM → Likely Scam', () => {
  const r = engine.analyze('Guaranteed 500% APY, risk-free staking, limited spots — DM me now to start earning!');
  eq(r.verdict.id, 'scam', 'verdict');
  hasFlag(r, 'guaranteed-returns');
  hasFlag(r, 'unrealistic-yield');
});

// 4. "DM me for guaranteed 10x" — High Risk.
check('DM for guaranteed 10x → High Risk', () => {
  const r = engine.analyze('DM me for guaranteed 10x returns, serious investors only.');
  eq(r.verdict.id, 'high', 'verdict');
  hasFlag(r, 'dm-solicitation');
  hasFlag(r, 'guaranteed-returns');
});

console.log('--- links (must flag) ---');

// 5. Lookalike Binance domain — Caution with typosquat flag.
check('Lookalike binance-secure-login.com → Caution', () => {
  const r = engine.analyze('https://binance-secure-login.com/verify');
  eq(r.verdict.id, 'caution', 'verdict');
  hasFlag(r, 'typosquat');
});

// 6. Punycode + lookalike — High Risk.
check('Punycode xn--binance → High Risk', () => {
  const r = engine.analyze('https://xn--binance-9xa.com/login');
  eq(r.verdict.id, 'high', 'verdict');
  hasFlag(r, 'punycode');
  hasFlag(r, 'typosquat');
});

// 7. Raw IP URL — Caution.
check('Raw IP URL → Caution', () => {
  const r = engine.analyze('http://185.220.101.5/wallet-verify');
  eq(r.verdict.id, 'caution', 'verdict');
  hasFlag(r, 'raw-ip');
});

// 8. Shortened link — Safe verdict but flag shown.
check('Shortened link → Safe, flag noted', () => {
  const r = engine.analyze('Check this out https://bit.ly/3xYz9Qa');
  eq(r.verdict.id, 'safe', 'verdict');
  hasFlag(r, 'shortener');
});

console.log('--- legit input (must pass) ---');

// 9. Plain market talk — Safe, score 0.
check('Market talk → Safe, score 0', () => {
  const r = engine.analyze('Bitcoin is trading at $97,000 today, up 2% on the day.');
  eq(r.verdict.id, 'safe', 'verdict');
  eq(r.score, 0, 'score');
  eq(r.flags.length, 0, 'flag count');
});

// 10. Real Binance URL — Safe.
check('Real binance.com URL → Safe', () => {
  const r = engine.analyze('https://www.binance.com/en/trade/BTC_USDT');
  eq(r.verdict.id, 'safe', 'verdict');
  noFlag(r, 'typosquat');
});

// 11. Real Coinbase mention + URL — Safe (no impersonation false positive).
check('Real Coinbase mention → Safe', () => {
  const r = engine.analyze('I bought 0.1 BTC on Coinbase yesterday — https://www.coinbase.com/buy');
  eq(r.verdict.id, 'safe', 'verdict');
  noFlag(r, 'impersonation');
});

// 12. Legit support mention — Safe (brand + "support" must not flag).
check('Binance support mention → Safe', () => {
  const r = engine.analyze('Binance support helped me reset my 2FA this morning, all sorted now.');
  eq(r.verdict.id, 'safe', 'verdict');
  noFlag(r, 'impersonation');
});

console.log('--- tricky edge cases ---');

// 13. Educational context quoting scam terms — Safe.
check('Educational explainer quoting scams → Safe', () => {
  const r = engine.analyze('This video explains how crypto giveaway scams work — never send funds to double your money.');
  eq(r.verdict.id, 'safe', 'verdict');
  if (r.score > 24) throw new Error('score too high for an explainer: ' + r.score);
  if (!r.educational) throw new Error('educational context not detected');
});

// 14. Safe seed-phrase advice — Safe (dampener applies).
check('Safe seed-phrase advice → Safe', () => {
  const r = engine.analyze('I moved my SOL to my Ledger yesterday — remember to keep your seed phrase offline and never share it with anyone.');
  eq(r.verdict.id, 'safe', 'verdict');
  if (r.score > 24) throw new Error('score too high for safe advice: ' + r.score);
});

// 15. Educational context does NOT dampen a malicious link.
check('Warning text with a lookalike link still flags the link', () => {
  const r = engine.analyze('Beware of this scam site going around: https://binance-secure-login.com/verify — never enter your password there.');
  hasFlag(r, 'typosquat');
  if (r.score < 25) throw new Error('lookalike link should still push score to Caution: ' + r.score);
});

console.log('--- token enrichment (pure, no network) ---');

// 16. No trading data → no-pairs flag.
check('Token with no pairs → no-pairs flag', () => {
  const flags = engine.enrichTokenData([]);
  if (!flags.some(f => f.id === 'no-pairs')) throw new Error('no-pairs flag missing');
  const merged = engine.mergeFlags(engine.analyze('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), flags);
  eq(merged.score, 15, 'merged score');
  eq(merged.verdict.id, 'safe', 'verdict');
});

// 17. Low liquidity + brand-new pair → flags.
check('Low-liquidity new pair → flags', () => {
  const flags = engine.enrichTokenData([
    { dexId: 'raydium', liquidity: { usd: 1200 }, pairCreatedAt: Date.now() }
  ]);
  if (!flags.some(f => f.id === 'low-liquidity')) throw new Error('low-liquidity flag missing');
  if (!flags.some(f => f.id === 'new-pair')) throw new Error('new-pair flag missing');
});

// 18. Healthy pair → no risk flags.
check('Healthy pair → no risk flags', () => {
  const flags = engine.enrichTokenData([
    { dexId: 'raydium', liquidity: { usd: 5000000 }, pairCreatedAt: Date.now() - 30 * 24 * 3600 * 1000 }
  ]);
  if (flags.some(f => f.weight > 0)) throw new Error('healthy pair should not add weight, got ' + JSON.stringify(flags));
});

console.log('--- verdict bands ---');

check('verdict bands', () => {
  eq(engine.verdictFor(0).id, 'safe', '0');
  eq(engine.verdictFor(24).id, 'safe', '24');
  eq(engine.verdictFor(25).id, 'caution', '25');
  eq(engine.verdictFor(49).id, 'caution', '49');
  eq(engine.verdictFor(50).id, 'high', '50');
  eq(engine.verdictFor(74).id, 'high', '74');
  eq(engine.verdictFor(75).id, 'scam', '75');
  eq(engine.verdictFor(100).id, 'scam', '100');
});

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed === 0 ? 0 : 1);
