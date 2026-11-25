/**
 * ScamShield end-to-end test (Playwright + headless Chromium).
 * Serves the app over local HTTP, loads it in a real browser, clicks the
 * sample chips, verifies the verdicts, captures the Devpost screenshots,
 * and exercises the live DexScreener lookup.
 *
 * Run:  node tests/e2e.js
 * Exits 0 when every check passes and no console/page errors occurred.
 */
const { chromium } = require('playwright-core');
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PORT = 8137;
const SHOTS = path.join(ROOT, 'screenshots');

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };

function serve() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const file = path.join(ROOT, req.url === '/' ? 'index.html' : decodeURIComponent(req.url.split('?')[0]));
      if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        res.writeHead(404); res.end('not found'); return;
      }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
      fs.createReadStream(file).pipe(res);
    });
    server.listen(PORT, () => resolve(server));
  });
}

(async () => {
  const server = await serve();
  const errors = [];
  let failed = 0;
  const check = (name, cond, extra) => {
    if (cond) console.log('  PASS  ' + name);
    else { failed++; console.log('  FAIL  ' + name + (extra ? ' — ' + extra : '')); }
  };

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    // A failed DexScreener request logs a resource error in the sandbox
    // (the API host is unreachable from the sandboxed browser). That is
    // the designed offline fallback, not an app error — ignore only that host.
    const loc = (m.location() && m.location().url) || '';
    if (/dexscreener\.com/i.test(m.text()) || /dexscreener\.com/i.test(loc)) return;
    errors.push('console: ' + m.text());
  });
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message));

  try {
    await page.goto('http://localhost:' + PORT + '/index.html', { waitUntil: 'networkidle' });
    check('page loads, title correct', (await page.title()).includes('ScamShield'));
    await page.screenshot({ path: path.join(SHOTS, '01-landing.png') });
    console.log('  shot   screenshots/01-landing.png');

    // 1) Scam sample -> Likely Scam.
    await page.click('[data-sample="scam"]');
    await page.waitForSelector('#verdictBadge', { state: 'visible' });
    await page.waitForTimeout(600);
    const scamVerdict = await page.textContent('#verdictBadge');
    const scamScore = await page.textContent('#scoreNum');
    check('scam sample verdict = Likely Scam', scamVerdict.trim() === 'Likely Scam', 'got "' + scamVerdict.trim() + '"');
    check('scam sample score >= 75', parseInt(scamScore, 10) >= 75, 'got ' + scamScore);
    await page.screenshot({ path: path.join(SHOTS, '02-high-risk.png') });
    console.log('  shot   screenshots/02-high-risk.png');

    // 2) Legit sample -> Safe.
    await page.click('[data-sample="legit"]');
    await page.waitForTimeout(600);
    const legitVerdict = await page.textContent('#verdictBadge');
    const legitScore = await page.textContent('#scoreNum');
    check('legit sample verdict = Safe', legitVerdict.trim() === 'Safe', 'got "' + legitVerdict.trim() + '"');
    check('legit sample score < 25', parseInt(legitScore, 10) < 25, 'got ' + legitScore);
    await page.screenshot({ path: path.join(SHOTS, '03-safe.png') });
    console.log('  shot   screenshots/03-safe.png');

    // 3) Link sample -> Likely Scam (phishing link + urgency).
    await page.click('[data-sample="link"]');
    await page.waitForTimeout(600);
    const linkVerdict = await page.textContent('#verdictBadge');
    check('link sample verdict = Likely Scam', linkVerdict.trim() === 'Likely Scam', 'got "' + linkVerdict.trim() + '"');

    // 4) Live DexScreener lookup with USDC (Solana).
    await page.fill('#input', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v');
    await page.click('#analyzeBtn');
    await page.waitForFunction(() => {
      const t = document.getElementById('liveStatus').textContent;
      return t !== 'checking…' && t !== 'not checked yet';
    }, { timeout: 15000 }).catch(() => {});
    const liveText = (await page.textContent('#liveStatus')).trim();
    const tokenFlags = await page.$$eval('.flag-label', (els) => els.map((e) => e.textContent));
    console.log('  info   DexScreener live status: "' + liveText + '"');
    console.log('  info   token flags shown: ' + JSON.stringify(tokenFlags));
    check('live lookup resolved (live or honest offline)', /live|offline|no trading data/.test(liveText), 'got "' + liveText + '"');
    await page.screenshot({ path: path.join(SHOTS, '04-token.png') });
    console.log('  shot   screenshots/04-token.png');

    check('no console/page errors', errors.length === 0, errors.join(' | '));
  } finally {
    await browser.close();
    server.close();
  }

  console.log(failed === 0 && errors.length === 0 ? '\nE2E: all checks passed' : '\nE2E: ' + failed + ' check(s) failed');
  process.exit(failed === 0 && errors.length === 0 ? 0 : 1);
})().catch((e) => { console.error('E2E crashed:', e); process.exit(1); });
