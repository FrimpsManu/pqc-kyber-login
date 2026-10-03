// Usage: node e2e.js <base-url> <screenshot-dir> <label>
// Uses the installed Google Chrome (macOS path below).

const puppeteer = require('puppeteer-core');
const fs = require('fs');
const BASE = process.argv[2] || 'http://127.0.0.1:8000';
const OUT = process.argv[3];
const tag = process.argv[4] || 'local';
const log = [];
const say = (s) => { console.log(s); log.push(s); };
(async () => {
  const browser = await puppeteer.launch({
    executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    headless: 'new', defaultViewport: { width: 1100, height: 800, deviceScaleFactor: 2 } });
  const page = await browser.newPage();
  const bodies = [];
  page.on('request', r => { if (r.url().includes('/api/')) bodies.push({ url: r.url(), body: r.postData() || '' }); });
  page.on('pageerror', e => say('PAGE ERROR: ' + e.message));
  const user = 'augustine' + (tag === 'local' ? '' : Date.now().toString().slice(-5));
  const pw = 'Kyber-Demo-' + Math.random().toString(36).slice(2, 8);
  say(`Target: ${BASE}   user: ${user}`);

  await page.goto(BASE + '/signup', { waitUntil: 'networkidle0' });
  await page.type('input[name=username]', user);
  await page.type('input[name=password]', pw);
  await page.type('input[name=confirm]', pw);
  await page.screenshot({ path: `${OUT}/${tag}-1-signup.png` });
  await Promise.all([page.waitForNavigation(), page.click('button[type=submit]')]);
  say('Sign-up -> ' + page.url());
  await page.screenshot({ path: `${OUT}/${tag}-2-dashboard-after-signup.png`, fullPage: true });

  await page.click('form.encrypt-form button');
  await page.waitForNavigation();
  const dec = await page.$eval('pre.plain', e => e.textContent);
  const checks = await page.$$eval('.checks td', tds => tds.map(t => t.textContent));
  say('Dashboard decrypted text: ' + dec + '   checks: ' + checks.join(','));
  await page.screenshot({ path: `${OUT}/${tag}-3-message-encrypted.png`, fullPage: true });

  await page.goto(BASE + '/logout', { waitUntil: 'networkidle0' });
  await page.type('input[name=username]', user);
  await page.type('input[name=password]', 'wrong-password');
  await page.click('button[type=submit]');
  await page.waitForSelector('.status.error');
  say('Wrong password message: ' + await page.$eval('#status', e => e.textContent));
  await page.screenshot({ path: `${OUT}/${tag}-4-wrong-password.png` });

  await page.$eval('input[name=password]', e => e.value = '');
  await page.type('input[name=password]', pw);
  await Promise.all([page.waitForNavigation(), page.click('button[type=submit]')]);
  say('Login -> ' + page.url());
  await page.screenshot({ path: `${OUT}/${tag}-5-dashboard-after-login.png`, fullPage: true });

  const leaked = bodies.some(b => b.body.includes(pw));
  say(`API requests captured: ${bodies.length}; password visible in any request body: ${leaked ? 'YES (FAIL)' : 'no'}`);
  const loginReq = bodies.filter(b => b.url.endsWith('/api/login')).pop();
  say('Example /api/login request body (truncated): ' + loginReq.body.slice(0, 300) + '...');
  fs.writeFileSync(`${OUT}/../${tag}_browser_test.txt`, log.join('\n') + '\n');
  await browser.close();
  process.exit(leaked ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
