/**
 * ScamShield — UI wiring.
 *
 * Flow: read input -> ScamShield.analyze() (local, deterministic) ->
 * render verdict -> if a token address was found, try the keyless public
 * DexScreener API for live pair/liquidity data and merge the extra flags.
 * If the lookup fails (offline, blocked, timeout), the local result stands
 * and the UI says so honestly.
 */
(function () {
  'use strict';

  var SAMPLES = {
    scam: '🚀 ELON MUSK GIVEAWAY! Send 0.5 ETH to 0x7f3a9c2e1b4d8f6a0c5e9b2d4f6a8c0e1b3d5f7 and receive 1 ETH back! Limited time, act now before it ends!',
    link: 'URGENT: Verify your Binance account now: https://binance-secure-login.com/verify — your funds will be frozen if you don\'t act in 24 hours!',
    legit: 'Bitcoin is trading around $97,000 today. I moved some SOL to my Ledger yesterday — remember to keep your seed phrase offline and never share it with anyone.'
  };

  var NEXT_STEPS = {
    safe: [
      'No red flags found — but stay alert: scams evolve daily.',
      'Still double-check any link by typing the official domain yourself instead of clicking.',
      'Never share your seed phrase or private key with anyone, ever.'
    ],
    caution: [
      'Do not send funds or connect your wallet until you have verified this independently.',
      'Check the sender and the link through official channels (the project’s real website or verified social account).',
      'If it arrived unsolicited, treat it as suspicious until proven otherwise.'
    ],
    high: [
      'Do not send funds. Do not connect your wallet. Do not enter your seed phrase anywhere.',
      'If you already interacted with it, move your funds to a fresh wallet immediately.',
      'Report the account, link or address on the platform where you found it.'
    ],
    scam: [
      'Do not send funds. Do not connect your wallet. Do not enter your seed phrase anywhere.',
      'If you already sent funds, they are almost certainly gone — still report it, and warn others.',
      'Report the account, link or address on the platform where you found it, and check your wallet approvals for anything malicious.'
    ]
  };

  var CATEGORY_LABELS = { message: 'Message red flags', link: 'Link red flags', token: 'Token checks' };

  var inputEl = document.getElementById('input');
  var analyzeBtn = document.getElementById('analyzeBtn');
  var clearBtn = document.getElementById('clearBtn');
  var resultsEl = document.getElementById('results');
  var livePill = document.getElementById('livePill');
  var liveStatus = document.getElementById('liveStatus');

  function setLive(status, state) {
    liveStatus.textContent = status;
    livePill.classList.remove('live', 'offline');
    if (state) livePill.classList.add(state);
  }

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function render(result) {
    var badge = document.getElementById('verdictBadge');
    badge.textContent = result.verdict.label;
    badge.className = 'verdict-badge ' + result.verdict.color;

    document.getElementById('scoreNum').textContent = result.score;
    document.getElementById('meterMarker').style.left = result.score + '%';
    document.getElementById('inputType').textContent =
      result.inputType === 'token' ? 'Detected: token address' :
      result.inputType === 'link' ? 'Detected: link' :
      'Detected: message / post';

    // Flags grouped by category.
    var groupsEl = document.getElementById('flagGroups');
    groupsEl.innerHTML = '';
    var grouped = {};
    result.flags.forEach(function (f) {
      (grouped[f.category] = grouped[f.category] || []).push(f);
    });
    var order = ['message', 'link', 'token'];
    var anyFlags = false;
    order.forEach(function (cat) {
      var list = grouped[cat];
      if (!list || !list.length) return;
      anyFlags = true;
      groupsEl.appendChild(el('div', 'flag-group-title', CATEGORY_LABELS[cat] || cat));
      list.forEach(function (f) {
        var row = el('div', 'flag');
        row.appendChild(el('span', 'sev-dot ' + f.severity));
        var body = el('div', 'flag-body');
        body.appendChild(el('div', 'flag-label', f.label));
        body.appendChild(el('div', 'flag-expl', f.explanation));
        row.appendChild(body);
        if (f.weight > 0) row.appendChild(el('span', 'flag-weight', '+' + f.weight));
        groupsEl.appendChild(row);
      });
    });
    document.getElementById('flagsEmpty').hidden = anyFlags;

    // Notes (info).
    var notesEl = document.getElementById('notesList');
    notesEl.innerHTML = '';
    (result.notes || []).forEach(function (n) {
      var note = el('div', 'note');
      note.appendChild(el('strong', null, n.label));
      note.appendChild(el('span', null, n.explanation));
      notesEl.appendChild(note);
    });

    // Next steps.
    var stepsEl = document.getElementById('nextSteps');
    stepsEl.innerHTML = '';
    (NEXT_STEPS[result.verdict.id] || NEXT_STEPS.safe).forEach(function (s) {
      stepsEl.appendChild(el('li', null, s));
    });

    resultsEl.hidden = false;
    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function reportText(result) {
    var lines = ['ScamShield report', 'Verdict: ' + result.verdict.label + ' (' + result.score + '/100)', ''];
    result.flags.forEach(function (f) {
      lines.push('- [' + f.category + '] ' + f.label + (f.weight ? ' (+' + f.weight + ')' : '') + ' — ' + f.explanation);
    });
    if (!result.flags.length) lines.push('- No red flags found.');
    lines.push('', 'Checked with ScamShield (SLAY HACKS 2026). Not financial advice.');
    return lines.join('\n');
  }

  var lastResult = null;

  async function analyze() {
    var text = inputEl.value.trim();
    if (!text) {
      inputEl.focus();
      return;
    }
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing…';

    var result = ScamShield.analyze(text);
    lastResult = result;
    setLive('checking…', null);
    render(result);

    // Live token data (optional, keyless DexScreener API).
    if (result.addresses && result.addresses.length > 0) {
      var addr = result.addresses[0].address;
      try {
        var ctrl = new AbortController();
        var timer = setTimeout(function () { ctrl.abort(); }, 8000);
        var res = await fetch('https://api.dexscreener.com/latest/dex/tokens/' + encodeURIComponent(addr), { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) throw new Error('HTTP ' + res.status);
        var data = await res.json();
        var extra = ScamShield.enrichTokenData(data && data.pairs);
        var merged = ScamShield.mergeFlags(result, extra);
        lastResult = merged;
        setLive(extra.some(function (f) { return f.id === 'no-pairs'; }) ? 'no trading data' : 'live', extra.some(function (f) { return f.id === 'no-pairs'; }) ? 'offline' : 'live');
        render(merged);
      } catch (e) {
        setLive('offline — local checks only', 'offline');
      }
    } else {
      setLive('not needed for this input', null);
    }

    analyzeBtn.disabled = false;
    analyzeBtn.textContent = 'Analyze';
  }

  analyzeBtn.addEventListener('click', analyze);
  inputEl.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') analyze();
  });

  clearBtn.addEventListener('click', function () {
    inputEl.value = '';
    resultsEl.hidden = true;
    setLive('not checked yet', null);
    inputEl.focus();
  });

  document.querySelectorAll('.chip').forEach(function (chip) {
    chip.addEventListener('click', function () {
      inputEl.value = SAMPLES[chip.getAttribute('data-sample')] || '';
      analyze();
    });
  });

  document.getElementById('copyBtn').addEventListener('click', function () {
    if (!lastResult) return;
    var done = function () {
      var msg = document.getElementById('copyMsg');
      msg.hidden = false;
      setTimeout(function () { msg.hidden = true; }, 2000);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(reportText(lastResult)).then(done, done);
    } else {
      done();
    }
  });
})();
