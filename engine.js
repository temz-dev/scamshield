/**
 * ScamShield — analysis engine
 *
 * A transparent, deterministic scoring engine for crypto scam detection.
 * No LLM, no server, no data leaves the browser (except the optional
 * keyless DexScreener lookup, which the UI performs separately).
 *
 * How scoring works:
 *  - Every check that fires adds its weight to the score (0-100, capped).
 *  - Verdict bands:  0-24 Safe · 25-49 Caution · 50-74 High Risk · 75-100 Likely Scam
 *  - Educational dampener: if the text is clearly a warning / explainer
 *    ("how to spot", "beware", "never send", ...), text-pattern weights are
 *    multiplied by 0.25, so scam terms quoted in an explainer do not flag
 *    the explainer itself. URL and token checks are never dampened — a
 *    malicious link is malicious even inside a warning.
 *
 * Works in the browser (window.ScamShield) and in Node (module.exports)
 * so the same code is used by the app and by the test suite.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ScamShield = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Knowledge base
  // ---------------------------------------------------------------------------

  // Brands scammers impersonate most, with their real domains.
  var OFFICIAL_DOMAINS = {
    binance: 'binance.com',
    coinbase: 'coinbase.com',
    metamask: 'metamask.io',
    uniswap: 'uniswap.org',
    kraken: 'kraken.com',
    ledger: 'ledger.com',
    trezor: 'trezor.io',
    phantom: 'phantom.app',
    solana: 'solana.com',
    trustwallet: 'trustwallet.com',
    bybit: 'bybit.com',
    okx: 'okx.com',
    gemini: 'gemini.com',
    opensea: 'opensea.io',
    pancakeswap: 'pancakeswap.finance',
    raydium: 'raydium.io',
    jupiter: 'jup.ag',
    'crypto.com': 'crypto.com',
    exodus: 'exodus.com'
  };

  var KNOWN_PEOPLE = [
    'elon musk', 'vitalik buterin', 'changpeng zhao', 'cz',
    'satoshi nakamoto', 'michael saylor', 'brian armstrong'
  ];

  // TLDs disproportionately abused by scam sites (legit sites rarely use them).
  var SUSPICIOUS_TLDS = [
    'xyz', 'top', 'click', 'buzz', 'live', 'info', 'online', 'site',
    'fun', 'icu', 'cc', 'su', 'pw', 'gq', 'ml', 'tk', 'cf', 'ga',
    'work', 'link', 'shop', 'vip', 'cam', 'bar', 'rest', 'mom', 'uno',
    'zip', 'mov', 'quest', 'bond', 'sbs', 'monster'
  ];

  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorturl.at', 'rebrand.ly', 'cutt.ly',
    'shorte.st', 't.ly', 'tiny.cc', 'rb.gy', 's.id'
  ];

  // Phrases that mark the text as a warning / explainer, not a solicitation.
  var EDUCATIONAL_RE = /(how to (spot|avoid|identify|detect))|beware (of)?|scam alert|educational|learn (how|about)|never (send|share|give)|do(n't| not) (send|share)|warning|stay safe|red flag|watch out|common scam/i;

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function levenshtein(a, b) {
    if (a === b) return 0;
    var m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    var prev = [], cur = [], i, j;
    for (j = 0; j <= n; j++) prev[j] = j;
    for (i = 1; i <= m; i++) {
      cur[0] = i;
      for (j = 1; j <= n; j++) {
        var cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      }
      var tmp = prev; prev = cur; cur = tmp;
    }
    return prev[n];
  }

  function hostWithoutWww(host) {
    return host.replace(/^www\./i, '');
  }

  function registrableDomain(host) {
    var parts = hostWithoutWww(host).split('.');
    if (parts.length <= 2) return parts.join('.');
    return parts.slice(-2).join('.');
  }

  // ---------------------------------------------------------------------------
  // Text-pattern checks
  // ---------------------------------------------------------------------------
  // Each entry: id, label, explanation, weight, severity, test(text) -> bool

  var TEXT_CHECKS = [
    {
      id: 'doubling',
      label: '“Send X, get 2X back” promise',
      explanation: 'No legitimate giveaway asks you to send crypto first and promises to double it. This is the classic giveaway-scam script.',
      weight: 30, severity: 'critical',
      test: function (t) {
        if (/doubl(e|ing) your (eth|btc|sol|crypto|money|investment|funds?)/i.test(t)) return true;
        if (/(send|deposit|transfer)\s+[\d.]+\s*\w*\s*(and|to)?\s*(get|receive|earn|back|win)\b[^.]{0,60}(2x|double|twice|2\s?times)/i.test(t)) return true;
        // Numeric form: "send 0.5 ETH ... receive 1 ETH back" (2x payout implied).
        var m = /(send|deposit|transfer)\s+(\d+(?:\.\d+)?)\s*(eth|btc|sol|usdt|usdc|bnb|xrp|doge|ada)\b[^.]{0,120}?(?:get|receive|earn|back)\s+(\d+(?:\.\d+)?)\s*\3\b/i.exec(t);
        if (m && parseFloat(m[4]) >= parseFloat(m[2]) * 1.9) return true;
        return false;
      }
    },
    {
      id: 'guaranteed-returns',
      label: 'Guaranteed returns',
      explanation: 'Real investments never guarantee returns. “Guaranteed profit” is a promise no honest project can make.',
      weight: 25, severity: 'critical',
      test: function (t) {
        return /guaranteed[^.]{0,20}?(return|profit|income|gains?|yield|apy|apr|payout|earnings?)/i.test(t)
          || /100%\s+(guaranteed|safe|profit|return)/i.test(t);
      }
    },
    {
      id: 'risk-free',
      label: '“Risk-free” profit claim',
      explanation: 'There is no risk-free way to earn high returns in crypto. The claim exists to lower your guard.',
      weight: 15, severity: 'warning',
      test: function (t) { return /risk[-\s]?free\s+(profit|return|investment|staking|yield|income|earnings?|trading)/i.test(t); }
    },
    {
      id: 'seed-phrase',
      label: 'Asks for a seed phrase',
      explanation: 'Your seed phrase is the master key to your wallet. No real support team, exchange or app will ever ask for it — anyone who has it owns your funds.',
      weight: 35, severity: 'critical',
      test: function (t) {
        return /(enter|share|send|provide|give|type|input|confirm|submit|paste)\b[^.]{0,40}\bseed phrase\b/i.test(t)
          || /\bseed phrase\b[^.]{0,40}\b(enter|share|send|provide|give|type|input|confirm|required|needed|verify)\b/i.test(t);
      }
    },
    {
      id: 'private-key',
      label: 'Asks for a private key',
      explanation: 'A private key gives full control of a wallet. Legitimate services never ask you to reveal one.',
      weight: 35, severity: 'critical',
      test: function (t) {
        return /(enter|share|send|provide|give|type|input|confirm|submit|paste)\b[^.]{0,40}\bprivate key\b/i.test(t)
          || /\bprivate key\b[^.]{0,40}\b(enter|share|send|provide|give|type|input|confirm|required|needed|verify)\b/i.test(t);
      }
    },
    {
      id: 'verify-wallet',
      label: '“Verify your wallet” lure',
      explanation: 'Fake verification pages are built to steal your seed phrase or get you to sign a malicious transaction. Real wallets never ask you to verify this way.',
      weight: 25, severity: 'critical',
      test: function (t) { return /verify your ([\w\s]{0,20}?)(wallet|account)/i.test(t) || /wallet verification/i.test(t); }
    },
    {
      id: 'giveaway',
      label: 'Giveaway claim',
      explanation: '“Free crypto giveaways” from celebrities or exchanges are almost always fake — the real ones never ask you to send funds first.',
      weight: 20, severity: 'warning',
      test: function (t) { return /\bgiveaway\b/i.test(t); }
    },
    {
      id: 'airdrop',
      label: 'Airdrop claim',
      explanation: 'Real airdrops never ask you to connect to a random site or send funds to “claim”. Fake airdrop pages drain wallets.',
      weight: 10, severity: 'info',
      test: function (t) { return /\bairdrop\b/i.test(t); }
    },
    {
      id: 'impersonation',
      label: 'Impersonation of a known figure or brand',
      explanation: 'Scammers pose as Elon Musk, Binance, Coinbase and other trusted names to borrow credibility. Check the account and the URL, not the name.',
      weight: 20, severity: 'critical',
      test: function (t) {
        var lower = t.toLowerCase();
        var promo = /(giveaway|airdrop|double|free|claim|promo|offer)/i.test(t);
        if (!promo) return false;
        var names = KNOWN_PEOPLE.concat(Object.keys(OFFICIAL_DOMAINS));
        for (var i = 0; i < names.length; i++) {
          if (lower.indexOf(names[i]) !== -1) return true;
        }
        return false;
      }
    },
    {
      id: 'urgency',
      label: 'Urgency / pressure language',
      explanation: '“Act now or lose everything” is designed to stop you thinking. Legitimate opportunities do not expire in an hour.',
      weight: 10, severity: 'warning',
      test: function (t) {
        return /(act now|limited (time|spots?|offer|seats?)|last chance|hurry|ending soon|act fast|don'?t miss|expires? (in|soon)|act (in|within) \d+ (minutes?|hours?|days?)|only \d+ (left|spots?|remaining)|claim (now|before)|within (the next )?\d+ (minutes?|hours?))/i.test(t);
      }
    },
    {
      id: 'unrealistic-yield',
      label: 'Unrealistic yield promise',
      explanation: 'Promises like 500% APY or “10x guaranteed” are not how real markets work. High promised returns are the bait.',
      weight: 20, severity: 'warning',
      test: function (t) {
        return /\b\d{3,}%\s*(apy|apr|returns?|profit|yield|per (day|week|month))/i.test(t)
          || /\b(10x|20x|50x|100x)\b[^.]{0,30}(guaranteed|profit|return|gains?)/i.test(t)
          || /(guaranteed|earn).{0,30}\b(10x|20x|50x|100x)\b/i.test(t);
      }
    },
    {
      id: 'dm-solicitation',
      label: 'DM / private-message solicitation',
      explanation: 'Real projects do not slide into your DMs offering investment deals. Private-message pitches are a hallmark of pig-butchering and giveaway scams.',
      weight: 10, severity: 'warning',
      test: function (t) {
        return /(dm|pm) me\b/i.test(t)
          || /message me (on|via|through)/i.test(t)
          || /contact me on (telegram|whatsapp)/i.test(t);
      }
    },
    {
      id: 'send-funds',
      label: 'Instruction to send crypto to an address',
      explanation: 'Being told to send funds to an address in a message is the core move of most crypto scams. Sending is irreversible.',
      weight: 15, severity: 'warning',
      test: function (t) {
        return /(send|deposit|transfer)\s+[\d.]+\s*(eth|btc|sol|usdt|usdc|bnb|xrp|doge|ada)\b[^.]{0,40}\b(to|at)\b/i.test(t);
      }
    }
  ];

  // ---------------------------------------------------------------------------
  // URL checks
  // ---------------------------------------------------------------------------

  var URL_RE = /\b(?:https?:\/\/)?(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:\/[^\s]*)?/gi;
  var IP_URL_RE = /\bhttps?:\/\/\d+\.\d+\.\d+\.\d+(?:\/[^\s]*)?/gi;

  function parseUrl(raw) {
    var candidate = raw;
    if (!/^https?:\/\//i.test(candidate)) candidate = 'https://' + candidate;
    try {
      var u = new URL(candidate);
      // Raw IP hosts are valid for the check (they are the point of it).
      if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) return u;
      // Require something that looks like a real host (has a dot and a TLD).
      if (!/\.[a-z]{2,}$/i.test(u.hostname)) return null;
      return u;
    } catch (e) {
      return null;
    }
  }

  function checkUrl(raw) {
    var flags = [];
    var u = parseUrl(raw);
    if (!u) return flags;
    var host = hostWithoutWww(u.hostname.toLowerCase());
    var reg = registrableDomain(host);
    var tld = host.split('.').pop();

    // Raw IP address as host — no domain at all.
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      flags.push({
        id: 'raw-ip', category: 'link', severity: 'critical', weight: 30,
        label: 'Link uses a raw IP address, not a domain',
        explanation: 'Legitimate services use named domains. Scam sites hide behind bare IP addresses so they cannot be looked up or reported easily.'
      });
      return flags;
    }

    // Punycode (xn--) — the classic homograph trick.
    if (host.indexOf('xn--') !== -1) {
      flags.push({
        id: 'punycode', category: 'link', severity: 'critical', weight: 25,
        label: 'Link uses punycode (xn--) — possible lookalike letters',
        explanation: 'Punycode lets attackers register domains that look identical to real ones using lookalike characters from other alphabets.'
      });
    }

    // URL shortener hides the real destination.
    if (SHORTENERS.indexOf(reg) !== -1 || SHORTENERS.indexOf(host) !== -1) {
      flags.push({
        id: 'shortener', category: 'link', severity: 'warning', weight: 15,
        label: 'Shortened link hides the real destination',
        explanation: 'Shorteners are handy, but scammers use them to hide where a link really goes. Expand it before clicking.'
      });
    }

    // Suspicious TLD.
    if (SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      flags.push({
        id: 'suspicious-tld', category: 'link', severity: 'warning', weight: 10,
        label: 'Unusual domain ending (.' + tld + ')',
        explanation: 'Scam sites overwhelmingly use cheap, throwaway endings like .' + tld + '. Real exchanges and wallets use .com, .io or .org.'
      });
    }

    // Not HTTPS.
    if (u.protocol === 'http:') {
      flags.push({
        id: 'http-insecure', category: 'link', severity: 'info', weight: 5,
        label: 'Link is plain HTTP, not HTTPS',
        explanation: 'A crypto or finance page without HTTPS is a bad sign on its own — and it is trivially easy to fake.'
      });
    }

    // Typosquat / lookalike of a known brand.
    var brandNames = Object.keys(OFFICIAL_DOMAINS);
    for (var i = 0; i < brandNames.length; i++) {
      var brand = brandNames[i];
      var official = OFFICIAL_DOMAINS[brand];
      if (reg === official) continue; // the real domain — fine.
      var hostPart = host.split('.').slice(0, -1).join('');
      var flagged = false;
      var detail = '';
      if (hostPart.indexOf(brand.replace('.', '')) !== -1 && hostPart !== brand.replace('.', '')) {
        // e.g. binance-support, binance-login, coinbase-verify, mybinance
        flagged = true;
        detail = '“' + host + '” contains the name “' + brand + '” but is not ' + official + '.';
      } else if (levenshtein(hostPart, brand.replace('.', '')) <= 2 && hostPart.length >= 5) {
        flagged = true;
        detail = '“' + host + '” is one or two letters away from “' + brand + '” — a classic typo-squat.';
      } else if (host.indexOf(brand.replace('.', '')) !== -1 && reg !== official) {
        // brand appears anywhere (e.g. as a subdomain: binance.com.evil.com)
        flagged = true;
        detail = '“' + brand + '” appears in the link, but the real domain is ' + reg + ', not ' + official + '.';
      }
      if (flagged) {
        flags.push({
          id: 'typosquat', category: 'link', severity: 'critical', weight: 40,
          label: 'Lookalike domain of ' + brand,
          explanation: detail + ' Scammers register domains that look almost identical to trusted brands to steal logins and funds.'
        });
        break; // one typosquat flag per URL is enough
      }
    }

    return flags;
  }

  // ---------------------------------------------------------------------------
  // Token / address checks
  // ---------------------------------------------------------------------------

  var ETH_RE = /\b0x[a-fA-F0-9]{40}\b/g;
  var SOL_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g;

  function extractAddresses(textWithoutUrls) {
    var found = [];
    var m;
    ETH_RE.lastIndex = 0;
    while ((m = ETH_RE.exec(textWithoutUrls)) !== null) {
      found.push({ address: m[0], chain: 'ethereum' });
    }
    SOL_RE.lastIndex = 0;
    while ((m = SOL_RE.exec(textWithoutUrls)) !== null) {
      // Avoid matching long English words that happen to be base58-shaped.
      if (/[A-Z]/.test(m[0]) && /[a-z]/.test(m[0]) && /[0-9]/.test(m[0])) {
        found.push({ address: m[0], chain: 'solana' });
      }
    }
    return found;
  }

  /**
   * Turn a DexScreener /latest/dex/tokens/{address} response into flags.
   * Pure function (no network) so it is unit-testable.
   * `pairs` is the `pairs` array from the API response (or null/undefined).
   */
  function enrichTokenData(pairs) {
    var flags = [];
    if (!pairs || pairs.length === 0) {
      flags.push({
        id: 'no-pairs', category: 'token', severity: 'warning', weight: 15,
        label: 'No trading data found for this token',
        explanation: 'No exchange pair exists for this address on DexScreener. It may be brand new, fake, or simply not a traded token — either way, there is nothing to verify.'
      });
      return flags;
    }
    var sorted = pairs.slice().sort(function (a, b) {
      return ((b.liquidity && b.liquidity.usd) || 0) - ((a.liquidity && a.liquidity.usd) || 0);
    });
    var top = sorted[0];
    var liq = (top.liquidity && top.liquidity.usd) || 0;
    flags.push({
      id: 'token-found', category: 'token', severity: 'info', weight: 0,
      label: 'Trading pair found on ' + (top.dexId || 'a DEX'),
      explanation: 'The token trades on ' + (top.dexId || 'a decentralised exchange') + ' with about $' + Math.round(liq).toLocaleString('en-US') + ' of liquidity in its largest pair.'
    });
    if (liq < 5000) {
      flags.push({
        id: 'low-liquidity', category: 'token', severity: 'critical', weight: 25,
        label: 'Very low liquidity ($' + Math.round(liq).toLocaleString('en-US') + ')',
        explanation: 'With so little liquidity, the price can be moved or the pool drained easily — the classic setup for a rug pull.'
      });
    } else if (liq < 50000) {
      flags.push({
        id: 'low-liquidity', category: 'token', severity: 'warning', weight: 15,
        label: 'Low liquidity ($' + Math.round(liq).toLocaleString('en-US') + ')',
        explanation: 'Thin liquidity means big price swings and a harder exit. Treat small, illiquid tokens with extra caution.'
      });
    }
    if (top.pairCreatedAt && (Date.now() - top.pairCreatedAt) < 24 * 3600 * 1000) {
      flags.push({
        id: 'new-pair', category: 'token', severity: 'warning', weight: 10,
        label: 'Trading pair created less than 24 hours ago',
        explanation: 'Brand-new pairs have no track record. Most rug pulls happen in the first day of a token’s life.'
      });
    }
    return flags;
  }

  // ---------------------------------------------------------------------------
  // Main analysis
  // ---------------------------------------------------------------------------

  function verdictFor(score) {
    if (score >= 75) return { id: 'scam', label: 'Likely Scam', color: 'red' };
    if (score >= 50) return { id: 'high', label: 'High Risk', color: 'orange' };
    if (score >= 25) return { id: 'caution', label: 'Caution', color: 'amber' };
    return { id: 'safe', label: 'Safe', color: 'green' };
  }

  /**
   * Analyze pasted input (message, URL, or token address).
   * Returns { input, inputType, score, verdict, flags, notes, addresses, urls, educational }
   * This function is fully offline / deterministic. Live DexScreener data is
   * added afterwards by the UI via enrichTokenData() + mergeFlags().
   */
  function analyze(input) {
    var text = (input || '').trim();
    var flags = [];
    var notes = [];

    if (!text) {
      return { input: text, inputType: 'empty', score: 0, verdict: verdictFor(0), flags: [], notes: [], addresses: [], urls: [], educational: false };
    }

    var educational = EDUCATIONAL_RE.test(text);
    if (educational) {
      notes.push({
        id: 'educational-context', category: 'info',
        label: 'Educational context detected',
        explanation: 'This reads like a warning or explainer, not a solicitation — scam terms quoted in it count for much less.'
      });
    }

    // --- text patterns (dampened in educational context) ---
    var damp = educational ? 0.25 : 1;
    TEXT_CHECKS.forEach(function (check) {
      if (check.test(text)) {
        var w = Math.round(check.weight * damp);
        flags.push({
          id: check.id, category: 'message', severity: check.severity,
          weight: w, label: check.label, explanation: check.explanation
        });
      }
    });

    // --- URLs ---
    var urls = [];
    var urlMatches = text.match(URL_RE) || [];
    (text.match(IP_URL_RE) || []).forEach(function (ip) {
      if (urlMatches.indexOf(ip) === -1) urlMatches.push(ip);
    });
    urlMatches.forEach(function (raw) {
      var u = parseUrl(raw);
      if (u) {
        urls.push(u.href);
        checkUrl(raw).forEach(function (f) { flags.push(f); });
      }
    });

    // --- token addresses (URLs stripped first so links are not misread) ---
    var textNoUrls = text.replace(URL_RE, ' ');
    var addresses = extractAddresses(textNoUrls);
    addresses.forEach(function (a) {
      flags.push({
        id: 'address-format', category: 'token', severity: 'info', weight: 0,
        label: 'Valid ' + (a.chain === 'ethereum' ? 'Ethereum' : 'Solana') + ' address format',
        explanation: 'The address is well-formed (' + a.address.slice(0, 10) + '…' + a.address.slice(-4) + '). Format alone says nothing about whether the token is legitimate — check its trading data.'
      });
    });

    // --- score & verdict ---
    var score = flags.reduce(function (sum, f) { return sum + (f.weight || 0); }, 0);
    score = Math.min(100, Math.max(0, score));

    if (flags.length === 0) {
      notes.push({
        id: 'no-flags', category: 'info',
        label: 'No red flags found',
        explanation: 'Nothing in this input matched the scam patterns, lookalike domains or address checks. That is a good sign — it is not a guarantee. Always verify through official channels before sending funds.'
      });
    }

    // Determine input type for display.
    var inputType = 'message';
    if (addresses.length > 0 && urls.length === 0 && text.split(/\s+/).length <= 2) inputType = 'token';
    else if (urls.length > 0 && text.split(/\s+/).length <= 3) inputType = 'link';

    return {
      input: text, inputType: inputType, score: score,
      verdict: verdictFor(score), flags: flags, notes: notes,
      addresses: addresses, urls: urls, educational: educational
    };
  }

  /**
   * Merge live-data flags (from enrichTokenData) into an analysis result
   * and recompute the score / verdict. Returns a new result object.
   */
  function mergeFlags(result, extraFlags) {
    var flags = result.flags.concat(extraFlags || []);
    var score = Math.min(100, flags.reduce(function (s, f) { return s + (f.weight || 0); }, 0));
    var out = {};
    Object.keys(result).forEach(function (k) { out[k] = result[k]; });
    out.flags = flags;
    out.score = score;
    out.verdict = verdictFor(score);
    return out;
  }

  return {
    analyze: analyze,
    enrichTokenData: enrichTokenData,
    mergeFlags: mergeFlags,
    verdictFor: verdictFor,
    checkUrl: checkUrl,
    extractAddresses: extractAddresses,
    TEXT_CHECKS: TEXT_CHECKS
  };
});
