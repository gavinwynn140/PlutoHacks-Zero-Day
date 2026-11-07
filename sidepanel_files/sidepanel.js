/* =====================================================================
   Zero Day: side panel logic

   Sections
     1. Config (scan settings live in config.js; other services plug in here)
     2. Small helpers
     3. Tabs
     4. Scan flow (button click -> read page -> sanitize -> analyze -> show)
     5. Page text extraction (runs inside the web page)
     6. PII sanitizing (the first privacy layer)
     7. AI analysis: Gemini placeholder + demo verdict
     8. Showing the verdict and threat meter
     9. Latest alerts feed
    10. Optional newsletter
    11. Community stories (forum mockup)
    12. Start-up
   ===================================================================== */
'use strict';

/* ---------------------------------------------------------------------
   1. CONFIG
   --------------------------------------------------------------------- */

// The scan service (proxy URL, Gemini key, model and instructions) is set up
// in config.js. People using Zero Day never enter or see a key.
// With neither a proxy nor a key set, scans run in demo mode.
const USE_MOCK_AI = !SCAN_PROXY_URL && !GEMINI_API_KEY;

// TODO(backend): your servers. Leave empty to use built-in sample data.
// Each needs CORS enabled for this extension, or a matching "host_permissions" entry.
const THREAT_FEED_URL = '';  // GET  -> { items: [ ...alerts, see fetchLatestThreats() ] }
const NEWSLETTER_URL  = '';  // POST -> { email }   (and DELETE to unsubscribe)
const COMMUNITY_URL   = '';  // GET posts / POST a new post (needs moderation on the server)

const MAX_PAGE_CHARS = 12000; // cap on page text sent for analysis

/* ---------------------------------------------------------------------
   2. SMALL HELPERS
   --------------------------------------------------------------------- */

const $ = (selector, root = document) => root.querySelector(selector);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Build elements with textContent only. We never use innerHTML, so nothing
// from a web page or a server can inject markup into the panel.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// Only allow normal web links.
function safeUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : '';
  } catch {
    return '';
  }
}

function prefersReducedMotion() {
  return document.documentElement.classList.contains('reduce-motion') ||
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

class ScanError extends Error {
  constructor(code, message, status) {
    super(message || code);
    this.code = code;
    this.status = status;   // HTTP status from the scan service, if there was one
  }
}

/* ---------------------------------------------------------------------
   3. TABS
   --------------------------------------------------------------------- */

const tabButtons = Array.from(document.querySelectorAll('.tab'));

function showTab(panelId, { focus = false } = {}) {
  tabButtons.forEach((button) => {
    const active = button.dataset.panel === panelId;
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
    document.getElementById(button.dataset.panel).hidden = !active;
    if (active && focus) button.focus();
  });
  if (panelId === 'panel-alerts') markAlertsSeen();
  $('.app-main').scrollTop = 0;
}

tabButtons.forEach((button, index) => {
  button.addEventListener('click', () => showTab(button.dataset.panel));
  button.addEventListener('keydown', (event) => {
    const last = tabButtons.length - 1;
    const target = {
      ArrowRight: index === last ? 0 : index + 1,
      ArrowLeft: index === 0 ? last : index - 1,
      Home: 0,
      End: last
    }[event.key];
    if (target !== undefined) {
      event.preventDefault();
      showTab(tabButtons[target].dataset.panel, { focus: true });
    }
  });
});

$('#open-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());

/* ---------------------------------------------------------------------
   4. SCAN FLOW
   --------------------------------------------------------------------- */

const scanButton = $('#scan-button');
const statusText = $('#scan-status');
const errorBox = $('#scan-error');
const homeView = $('#scan-home');
const resultsView = $('#scan-results');

let scannedTabId = null;   // the tab we scanned, so we can mark things on it
let scannedUrl = null;     // its address, so we can tell when the person moves on
let scanToken = 0;         // goes up on every scan and every reset; lets old scans stand down
let currentFindings = [];

scanButton.addEventListener('click', runScan);
$('#rescan-button').addEventListener('click', runScan);

async function runScan() {
  const token = ++scanToken;
  const stale = () => token !== scanToken;   // true if the person moved to another page meanwhile

  scanButton.disabled = true;
  scanButton.textContent = 'Scanning…';
  errorBox.hidden = true;
  resultsView.hidden = true;
  homeView.hidden = false;
  $('#scan-hero').hidden = true;
  await clearMarks();            // remove marks left from an earlier scan
  setProgress(8);
  let failed = false;

  try {
    setStatus('Reading this page…');
    const tab = await getActiveTab();
    if (stale()) return;
    scannedTabId = tab.id;
    scannedUrl = tab.url;
    if (isBrowserPage(tab.url)) throw new ScanError('browser-page', 'Chrome page');

    const page = await extractFromTab(tab.id);
    if (stale()) return;
    setProgress(35);

    setStatus('Hiding personal details…');
    const { payload, report } = buildSafePayload(page);
    renderPrivacyReport(report, payload.text);
    const findings = detectFindings(page);   // runs on this computer only
    setProgress(55);

    setStatus('Checking for warning signs…');
    const verdict = await analyzePage(payload);
    if (stale()) return;
    setProgress(100);

    setStatus('');
    renderResults(verdict, payload.host, findings);
  } catch (error) {
    if (stale()) return;
    setStatus('');
    setProgress(null);
    if (error instanceof ScanError && error.code === 'browser-page') {
      renderBrowserPageResult();
    } else {
      failed = true;
      showScanError(error);
    }
  } finally {
    if (!stale()) {
      scanButton.disabled = false;
      scanButton.textContent = failed ? 'Try again' : 'Analyze this page';
    }
  }
}

function setStatus(message) {
  statusText.textContent = message;
}

// percent: 0-100, or null to hide the bar
function setProgress(percent) {
  const bar = $('#progress');
  bar.hidden = percent === null;
  if (percent === null) return;
  $('#progress-fill').style.width = `${percent}%`;
  bar.setAttribute('aria-valuenow', String(percent));
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab || tab.id === undefined) {
    throw new ScanError('no-tab', 'No page is open to scan.');
  }
  return tab;
}

// Runs extractPageContent() inside the page. This only works if Chrome has
// granted access to the tab (see "No access" handling in showScanError).
async function extractFromTab(tabId) {
  let injection;
  try {
    [injection] = await chrome.scripting.executeScript({
      target: { tabId },
      func: extractPageContent,
      args: [MAX_PAGE_CHARS]
    });
  } catch (error) {
    const message = (error && error.message) || '';
    // Chrome refuses to let any extension read its own pages.
    if (/\b(?:chrome|chrome-extension|chrome-error|chrome-untrusted|devtools|edge|about|view-source):|extensions gallery/i.test(message)) {
      throw new ScanError('browser-page', message);
    }
    throw new ScanError('no-access', message);
  }
  if (!injection || !injection.result || !injection.result.text) {
    throw new ScanError('empty', 'No readable text on this page.');
  }
  return injection.result;
}

// Every error shows a short title and a calm explanation of what happened
// and what to do next, so nobody is left staring at a spinner.
const ERROR_COPY = {
  'no-access': {
    title: 'Zero Day needs your OK for this page',
    text: "Chrome hasn't given Zero Day access to this page yet. Click the Zero Day icon at the top of Chrome, then press Analyze this page again."
  },
  'empty': {
    title: 'Nothing to read here',
    text: "There wasn't any readable text on this page, so there was nothing to check."
  },
  'no-tab': {
    title: 'No page is open',
    text: 'Open a website or an email, then press Analyze this page.'
  },
  'busy': {
    title: 'The safety checker is very busy',
    text: "A lot of people are using it right now, or it is having a short hiccup. Nothing is wrong with your computer or this page. Wait about a minute, then press Try again."
  },
  'rate-limit': {
    title: 'Please wait a moment',
    text: 'The safety checker has had a lot of requests in a short time. Wait about a minute, then press Try again.'
  },
  'setup': {
    title: "The safety checker isn't working right now",
    text: "This is a problem on our side, not yours, and nothing you do will fix it. Please try again later."
  },
  'bad-request': {
    title: "We couldn't check this page",
    text: 'This page may be too large or unusual for the checker. Try a different page.'
  },
  'offline': {
    title: "Couldn't reach the safety checker",
    text: "This is usually an internet connection problem. Check that you're online, then press Try again."
  },
  'timeout': {
    title: 'This is taking too long',
    text: "The safety checker didn't answer in time. Press Try again in a moment."
  },
  'bad-answer': {
    title: 'We got an answer we could not read',
    text: 'This sometimes happens. Press Try again. If it keeps happening, try a different page.'
  },
  'api': {
    title: "The safety checker didn't answer",
    text: 'Please try again in a minute.'
  },
  'not-connected': {
    title: "The safety checker isn't connected yet",
    text: 'Please try again later.'
  }
};

function showScanError(error) {
  const code = error instanceof ScanError ? error.code : 'unknown';
  const copy = ERROR_COPY[code] || { title: 'Something went wrong', text: 'Please try again.' };
  let text = copy.text;
  if (DEBUG_SCAN && error && error.message) text += ` [Technical detail: ${error.message}]`;
  $('#scan-error-title').textContent = copy.title;
  $('#scan-error-text').textContent = text;
  $('#grant-button').hidden = code !== 'no-access';
  $('#grant-hint').hidden = code !== 'no-access';
  errorBox.hidden = false;
}

// Chrome's own pages can't be read by any extension. Show a calm 0% result
// that says exactly why, instead of an error.
const BROWSER_PAGE_RE = /^(?:chrome|chrome-extension|chrome-untrusted|chrome-search|chrome-error|devtools|edge|brave|opera|vivaldi|about|view-source):/i;

function isBrowserPage(url) {
  if (!url) return false;
  if (BROWSER_PAGE_RE.test(url)) return true;
  try {
    const { hostname, pathname } = new URL(url);
    return hostname === 'chromewebstore.google.com' || (hostname === 'chrome.google.com' && pathname.startsWith('/webstore'));
  } catch {
    return false;
  }
}

function renderBrowserPageResult() {
  renderResults({
    noScan: true,
    headline: "Zero Day can't read this page",
    verdict: "This is one of Chrome's own pages, such as Settings, Extensions, the New Tab page or the Chrome Web Store. Chrome doesn't let any extension read them, so nothing was checked. The 0% means 'not scanned', not 'confirmed safe'.",
    action_items: [
      'To scan something, open a website or an email in this tab, then press Analyze this page.',
      "If you wanted to check a link, open it first, then press Analyze."
    ]
  }, '', []);
}

// Optional: let the person allow scanning on every page so they don't have
// to click the toolbar icon after moving to a new site. Must be triggered by
// a click, which is why it's a button.
$('#grant-button').addEventListener('click', async () => {
  try {
    const granted = await chrome.permissions.request({ origins: ['<all_urls>'] });
    if (granted) runScan();
  } catch (error) {
    console.error('Zero Day: permission request failed', error);
  }
});

/* ---------------------------------------------------------------------
   5. PAGE TEXT EXTRACTION
   This function is serialized and run INSIDE the web page, so it can't use
   anything defined elsewhere in this file. It only reads visible text.
   It skips form fields, passwords and hidden elements on purpose, and
   removes query strings and #fragments from every URL (they often hold
   session tokens).
   --------------------------------------------------------------------- */
function extractPageContent(maxChars) {
  const SKIP = 'script,style,noscript,template,svg,canvas,iframe,input,textarea,select,option,[contenteditable],[aria-hidden="true"]';
  const tidy = (text) => text.replace(/\s+/g, ' ').trim();
  const stripUrl = (href) => {
    try {
      const url = new URL(href, location.href);
      if (url.protocol !== 'http:' && url.protocol !== 'https:') return '';
      return url.origin + url.pathname;
    } catch {
      return '';
    }
  };

  if (!document.body) return { title: '', url: stripUrl(location.href), text: '', links: [] };

  const parts = [];
  let total = 0;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent || parent.closest(SKIP)) return NodeFilter.FILTER_REJECT;
      if (parent.checkVisibility && !parent.checkVisibility()) return NodeFilter.FILTER_REJECT;
      return node.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
    }
  });
  while (total < maxChars && walker.nextNode()) {
    const piece = tidy(walker.currentNode.nodeValue);
    parts.push(piece);
    total += piece.length + 1;
  }

  // Link text vs. where the link really goes is a classic phishing clue.
  const links = Array.from(document.querySelectorAll('a[href]'))
    .slice(0, 40)
    .map((a) => ({ text: tidy(a.textContent).slice(0, 80), url: stripUrl(a.href) }))
    .filter((link) => link.url);

  return {
    title: tidy(document.title).slice(0, 200),
    url: stripUrl(location.href),
    text: parts.join(' ').slice(0, maxChars),
    links
  };
}

/* ---------------------------------------------------------------------
   6. PII SANITIZING  (first privacy layer; runs on this computer)
   Nothing is sent to any AI service until this has run.
   Regex can't catch everything (for example, people's names), which is why
   the Gemini instructions should ALSO tell the model to ignore personal
   details. That is the second layer.
   --------------------------------------------------------------------- */

// ==== SANITIZE START ====
function luhnCheck(candidate) {
  const digits = candidate.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = Number(digits[i]);
    if (double) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

// Order matters: more specific patterns run before broader ones.
const PII_RULES = [
  { id: 'email', names: ['email address', 'email addresses'],
    re: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, tag: '[EMAIL]' },
  { id: 'ssn', names: ['Social Security number', 'Social Security numbers'],
    re: /\b\d{3}-\d{2}-\d{4}\b/g, tag: '[SSN]' },
  { id: 'card', names: ['card number', 'card numbers'],
    re: /\b\d(?:[ -]?\d){12,18}\b/g, tag: '[CARD]', validate: luhnCheck },
  { id: 'phone', names: ['phone number', 'phone numbers'],
    re: /(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\w)/g, tag: '[PHONE]' },
  { id: 'ip', names: ['IP address', 'IP addresses'],
    re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, tag: '[IP]' },
  { id: 'address', names: ['street address', 'street addresses'],
    re: /\b\d{1,5}\s+(?:[A-Za-z0-9.'-]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter)\b\.?/gi, tag: '[ADDRESS]' },
  { id: 'birth', names: ['birth date', 'birth dates'],
    re: /\b(?:date of birth|dob|birthday|born on)\s*[:-]?\s*(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|[A-Za-z]{3,9}\.?\s+\d{1,2},?\s+\d{4})/gi, tag: '[BIRTHDATE]' },
  // Keeps the words ("verification code is") but hides the value.
  { id: 'secret-value', names: ['password or code', 'passwords or codes'],
    re: /\b((?:password|passcode|pin|one[- ]time code|verification code|security code)\s*(?:is|:|=)\s*)\S+/gi,
    tag: '[HIDDEN]', keepPrefix: true },
  { id: 'token', names: ['long secret key', 'long secret keys'],
    re: /\b[A-Za-z0-9_-]{32,}\b/g, tag: '[SECRET]',
    validate: (match) => /\d/.test(match) && /[A-Za-z]/.test(match) }
];

// Returns cleaned text. If you pass a `report` object, it is filled with
// counts of what was hidden, like { email: 2, phone: 1 }.
function sanitizePII(text, report = {}) {
  let output = String(text || '');
  for (const rule of PII_RULES) {
    output = output.replace(rule.re, (...args) => {
      const match = args[0];
      if (rule.validate && !rule.validate(match)) return match;
      report[rule.id] = (report[rule.id] || 0) + 1;
      return rule.keepPrefix ? args[1] + rule.tag : rule.tag;
    });
  }
  return output;
}
// ==== SANITIZE END ====

// Turns raw page content into the one object that is allowed to leave the browser.
function buildSafePayload(page) {
  const report = {};
  const clean = (value) => sanitizePII(value, report);

  let host = '';
  try { host = new URL(page.url).hostname; } catch { /* leave empty */ }

  const payload = {
    host,
    url: clean(page.url),
    title: clean(page.title),
    text: clean(page.text).slice(0, MAX_PAGE_CHARS),
    links: page.links.map((link) => ({ text: clean(link.text), url: clean(link.url) }))
  };
  return { payload, report };
}

function describeReport(report) {
  const parts = PII_RULES
    .filter((rule) => report[rule.id])
    .map((rule) => `${report[rule.id]} ${report[rule.id] === 1 ? rule.names[0] : rule.names[1]}`);
  if (!parts.length) return "We didn't find any personal details on this page.";
  return `Hidden before checking: ${new Intl.ListFormat('en', { style: 'long', type: 'conjunction' }).format(parts)}.`;
}

function renderPrivacyReport(report, cleanedText) {
  $('#privacy-report').textContent = describeReport(report);
  const preview = $('#privacy-preview');
  preview.textContent = 'What the checker sees (first part): ' + cleanedText.slice(0, 500);
  preview.hidden = false;
}

/* ---------------------------------------------------------------------
   6b. FINDINGS ("What we noticed")
   Simple checks that run on this computer, so each finding points to real
   words or links on the page and can be marked there. The AI verdict
   gives the overall percent and advice; these show the person WHY.
   Each finding: { id, kind: 'danger' | 'bait', title, detail, terms[], links[] }
   --------------------------------------------------------------------- */

const URGENCY_RE = /\b(?:act now|act immediately|immediately|urgent(?:ly)?|right away|within \d+ (?:hours?|minutes?)|final notice|last chance|limited time|expires? (?:today|soon|tonight)|(?:account|access) (?:will be |has been |is )?(?:suspended|locked|closed|disabled)|verify your (?:account|identity)|confirm your (?:password|identity|account)|your computer is infected|call (?:this|the following) number)\b/gi;
const BAIT_RE = /\b(?:you(?:['\u2019]ve| have) (?:won|been selected)|free (?:gift cards?|candy|prize|iphone|money|cash)|claim your (?:prize|reward|gift|winnings)|congratulations,? (?:you|winner)|gift cards?|lottery|inheritance|bitcoin|wire transfer)\b/gi;
const ASK_RE = /\b(?:enter|confirm|verify|send|provide|share|reply with|update)\s+(?:us\s+)?(?:your\s+)?(?:\w+\s+){0,2}?(?:password|social security(?: number)?|card number|credit card|bank account|pin|verification code|one[- ]time code)\b/gi;
const SENDER_RE = /\bfrom:?\s*(?:[^<@]{0,60}<)?([A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,}))/gi;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at']);
const RISKY_TLD = /\.(?:zip|top|xyz|click|country|gq|tk|ml|cf|ga|work|support|rest|icu)$/i;
const BRANDS = { paypal: 'paypal.com', amazon: 'amazon.com', microsoft: 'microsoft.com', apple: 'apple.com',
  netflix: 'netflix.com', google: 'google.com', usps: 'usps.com', fedex: 'fedex.com', irs: 'irs.gov',
  chase: 'chase.com', wellsfargo: 'wellsfargo.com', bankofamerica: 'bankofamerica.com' };

const hyphenCount = (text) => (text.match(/-/g) || []).length;
const sameSite = (a, b) => {
  const x = a.replace(/^www\./, '');
  const y = b.replace(/^www\./, '');
  return x === y || x.endsWith('.' + y) || y.endsWith('.' + x);
};

function hostLooksRisky(host) {
  const h = host.toLowerCase();
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || h.includes('xn--') || SHORTENERS.has(h) ||
    RISKY_TLD.test(h) || hyphenCount(h) >= 3;
}

// Up to `max` different matches (ignoring capital letters), in page order.
function uniqueMatches(re, text, max = 4) {
  const seen = new Set();
  const found = [];
  for (const match of text.matchAll(re)) {
    const key = match[0].toLowerCase();
    if (!seen.has(key)) { seen.add(key); found.push(match[0]); }
    if (found.length >= max) break;
  }
  return found;
}

const quoteList = (items) => items.slice(0, 3).map((item) => `\u201c${item}\u201d`).join(', ');

function senderFinding(text) {
  const bad = [];
  for (const match of text.matchAll(SENDER_RE)) {
    const address = match[1];
    const domain = match[2].toLowerCase();
    const brand = Object.keys(BRANDS).find((name) => domain.split(/[.-]/).includes(name));
    const fake = brand && !sameSite(domain, BRANDS[brand]);
    if ((fake || hostLooksRisky(domain) || hyphenCount(domain) >= 2) && !bad.includes(address)) bad.push(address);
    if (bad.length >= 2) break;
  }
  if (!bad.length) return null;
  return { id: 'sender', kind: 'danger', title: 'Suspicious sender address',
    detail: `The message says it is from ${bad.join(' and ')}`, terms: bad, links: [] };
}

function linkFinding(links) {
  const flagged = [];
  for (const link of links || []) {
    let host = '';
    try { host = new URL(link.url).hostname; } catch { continue; }
    const shownMatch = link.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
    const mismatch = shownMatch && !sameSite(shownMatch[1].toLowerCase(), host);
    if ((mismatch || hostLooksRisky(host)) && !flagged.some((item) => item.host === host && item.text === link.text)) {
      flagged.push({ text: link.text, host });
    }
    if (flagged.length >= 5) break;
  }
  if (!flagged.length) return null;
  const hosts = Array.from(new Set(flagged.map((item) => item.host)));
  return { id: 'links', kind: 'danger', title: 'Untrusted destination link',
    detail: `A link on this page goes to ${hosts.slice(0, 3).join(', ')}`, terms: [], links: flagged };
}

// Returns a list of findings, most worrying first.
function detectFindings(page) {
  const text = `${page.title} ${page.text}`;
  const list = [];
  const add = (item) => { if (item) list.push(item); };

  add(senderFinding(text));
  const bait = uniqueMatches(BAIT_RE, text);
  if (bait.length) add({ id: 'bait', kind: 'bait', title: 'Prize or too-good-to-be-true offer',
    detail: `Found: ${quoteList(bait)}`, terms: bait, links: [] });
  const urgency = uniqueMatches(URGENCY_RE, text);
  if (urgency.length) add({ id: 'urgency', kind: 'danger', title: 'Pressure to act quickly',
    detail: `Found: ${quoteList(urgency)}`, terms: urgency, links: [] });
  const asks = uniqueMatches(ASK_RE, text, 3);
  if (asks.length) add({ id: 'asks', kind: 'danger', title: 'Asks for private information',
    detail: `Found: ${quoteList(asks)}`, terms: asks, links: [] });
  add(linkFinding(page.links));
  return list;
}

/* ---------------------------------------------------------------------
   6c. MARKING FINDINGS ON THE PAGE
   highlightOnPage() is serialized and run INSIDE the web page, so it can't
   use anything else from this file. It only adds colored marks (and
   removes them again); it never changes what the page says or does.
   --------------------------------------------------------------------- */
function highlightOnPage(items, clearOnly) {
  const MARK = 'data-zeroday';
  const STYLE = {
    danger: 'background:#fecaca;color:#000;border-bottom:3px solid #ef4444;padding:1px 3px;border-radius:4px;',
    bait: 'background:#fde68a;color:#000;border-bottom:3px solid #f59e0b;padding:1px 3px;border-radius:4px;'
  };

  // 1) Remove marks from earlier.
  document.querySelectorAll(`mark[${MARK}]`).forEach((mark) => mark.replaceWith(document.createTextNode(mark.textContent)));
  document.querySelectorAll(`a[${MARK}]`).forEach((a) => {
    a.style.cssText = a.getAttribute('data-zeroday-style') || '';
    a.removeAttribute(MARK);
    a.removeAttribute('data-zeroday-style');
  });
  if (document.body) document.body.normalize();
  if (clearOnly || !document.body) return 0;

  let count = 0;
  let first = null;
  const SKIP = 'script,style,noscript,template,svg,canvas,iframe,input,textarea,select,option,mark';
  const escape = (word) => word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // 2) Mark words and phrases (spaces in a phrase match any gap in the page).
  for (const item of items) {
    for (const term of item.terms) {
      const re = new RegExp(term.trim().split(/\s+/).map(escape).join('\\s+'), 'gi');
      const nodes = [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const parent = walker.currentNode.parentElement;
        if (parent && !parent.closest(SKIP) && re.test(walker.currentNode.nodeValue)) nodes.push(walker.currentNode);
        re.lastIndex = 0;
      }
      for (const node of nodes) {
        const textValue = node.nodeValue;
        const fragment = document.createDocumentFragment();
        let last = 0;
        for (const match of textValue.matchAll(re)) {
          fragment.append(document.createTextNode(textValue.slice(last, match.index)));
          const mark = document.createElement('mark');
          mark.setAttribute(MARK, item.kind);
          mark.style.cssText = STYLE[item.kind] || STYLE.danger;
          mark.textContent = match[0];
          fragment.append(mark);
          first = first || mark;
          count++;
          last = match.index + match[0].length;
        }
        fragment.append(document.createTextNode(textValue.slice(last)));
        node.replaceWith(fragment);
      }
    }

    // 3) Mark links by where they go and what they say.
    for (const link of item.links || []) {
      document.querySelectorAll('a[href]').forEach((a) => {
        let host = '';
        try { host = new URL(a.href).hostname; } catch { return; }
        const shown = a.textContent.replace(/\s+/g, ' ').trim().slice(0, 80);
        if (host !== link.host || shown !== link.text || a.hasAttribute(MARK)) return;
        a.setAttribute('data-zeroday-style', a.style.cssText);
        a.setAttribute(MARK, item.kind);
        a.style.cssText += STYLE[item.kind] || STYLE.danger;
        first = first || a;
        count++;
      });
    }
  }

  if (first) first.scrollIntoView({ block: 'center', behavior: 'smooth' });
  return count;
}

async function runInPage(func, args) {
  if (scannedTabId === null) throw new Error('No scanned tab');
  const [injection] = await chrome.scripting.executeScript({ target: { tabId: scannedTabId }, func, args });
  return injection ? injection.result : 0;
}

const markItem = (finding) => ({ kind: finding.kind, terms: finding.terms, links: finding.links });

function setPressed(activeButton) {
  document.querySelectorAll('.finding-card').forEach((card) => {
    card.setAttribute('aria-pressed', String(activeButton === 'all' || card === activeButton));
  });
}

async function markFindings(list, activeButton) {
  const status = $('#mark-status');
  try {
    const count = await runInPage(highlightOnPage, [list.map(markItem), false]);
    setPressed(count ? activeButton : null);
    $('#clear-button').hidden = !count;
    status.textContent = count
      ? 'Marked on the page.'
      : "We couldn't find that on the page. It may have moved or changed.";
  } catch (error) {
    console.error('Zero Day: could not mark the page', error);
    status.textContent = "Zero Day can't mark this page right now. Click the Zero Day shield icon at the top of Chrome, then try again.";
  }
}

async function clearMarks() {
  try { if (scannedTabId !== null) await runInPage(highlightOnPage, [[], true]); } catch { /* tab closed or moved on */ }
  setPressed(null);
  $('#clear-button').hidden = true;
  $('#mark-status').textContent = '';
}

/* ---------------------------------------------------------------------
   6d. START OVER WHEN THE PERSON MOVES ON
   A result only describes the page that was scanned. As soon as the person
   switches tabs, opens a different page (including a different email in a
   single-page app), reloads, or closes the tab, the panel goes back to
   "Analyze this page" so an old answer is never shown for a new page.
   Uses only tab events, so no extra permission is needed.
   --------------------------------------------------------------------- */
function resetScan() {
  scanToken++;                 // any scan still running stands down
  clearMarks();                // best effort: tidy the old tab
  scannedTabId = null;
  scannedUrl = null;
  currentFindings = [];
  resultsView.hidden = true;
  homeView.hidden = false;
  $('#scan-hero').hidden = false;
  errorBox.hidden = true;
  setStatus('');
  setProgress(null);
  scanButton.disabled = false;
  scanButton.textContent = 'Analyze this page';
}

let panelWindowId = null;
chrome.windows.getCurrent().then((win) => { panelWindowId = win.id; }).catch(() => {});

chrome.tabs.onActivated.addListener(({ tabId, windowId }) => {
  if (panelWindowId !== null && windowId !== panelWindowId) return;   // another Chrome window
  if (scannedTabId !== null && tabId !== scannedTabId) resetScan();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (tabId === scannedTabId) resetScan();
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (tabId !== scannedTabId) return;
  if (changeInfo.status === 'loading') { resetScan(); return; }          // new page or reload
  if (changeInfo.url !== undefined) {                                     // address changed
    if (changeInfo.url !== scannedUrl) resetScan();
    return;
  }
  // Anything else (a title change, an app swapping views): check the address again.
  try {
    const tab = await chrome.tabs.get(tabId);
    if (tabId === scannedTabId && tab.url !== scannedUrl) resetScan();
  } catch {
    resetScan();
  }
});

$('#visual-button').addEventListener('click', () => markFindings(currentFindings, 'all'));
$('#clear-button').addEventListener('click', clearMarks);

/* ---------------------------------------------------------------------
   7. AI ANALYSIS
   The scan service (config.js) answers with this JSON:
   {
     "threat_level": "SAFE" | "CAUTION" | "DANGER",
     "meter_score":  1-100   (the percent chance this is a scam)
     "action_items": ["Short do-this-next step", ...],
     "verdict":      "A short paragraph explaining the decision"
   }
   normalizeVerdict() turns that into what the screen uses:
   { score, level, explanation, actions }
   --------------------------------------------------------------------- */

async function analyzePage(payload) {
  if (USE_MOCK_AI) {
    await delay(1100); // pretend to think so the meter sweep is visible
    return mockVerdict(payload);
  }
  return SCAN_PROXY_URL ? callScanProxy(payload) : callGemini(payload);
}

// Reads the model's JSON, even if it arrived wrapped in a code fence.
function parseVerdictJson(text) {
  try {
    return JSON.parse(String(text).replace(/^\s*```(?:json)?/i, '').replace(/```\s*$/, '').trim());
  } catch {
    throw new ScanError('bad-answer', 'The answer was not valid JSON');
  }
}

// Busy-server answers worth trying again automatically (usually 503 when the model is
// getting heavy traffic). After the last try, the person sees a clear "very busy" message.
const RETRY_STATUSES = new Set([429, 500, 502, 503, 504]);
const MAX_RETRIES = 2;
const REQUEST_TIMEOUT_MS = 30000;

function errorCodeForStatus(status, reason) {
  if (status === 429) return 'rate-limit';
  if ([500, 502, 503, 504].includes(status)) return 'busy';
  if (status === 401 || status === 403 || status === 404) return 'setup';
  // Google reports a bad key as a 400.
  if (status === 400) return /api key|permission|not found|billing/i.test(reason) ? 'setup' : 'bad-request';
  return 'api';
}

// fetch() that retries when the service is busy and turns every failure into
// a ScanError with a code that ERROR_COPY has a friendly message for.
async function postJson(url, headers, body, who) {
  for (let attempt = 0; ; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
        signal: controller.signal
      });
    } catch (error) {
      console.error(`Zero Day: could not reach ${who}`, error);
      if (error.name === 'AbortError') throw new ScanError('timeout', `${who} did not answer in ${REQUEST_TIMEOUT_MS / 1000}s`);
      // Offline, or Chrome blocked it (see the host_permissions note in config.js).
      throw new ScanError('offline', `Could not reach ${who} (${error.message})`);
    } finally {
      clearTimeout(timer);
    }

    if (response.ok) {
      try {
        return await response.json();
      } catch {
        throw new ScanError('bad-answer', `${who} sent something that was not JSON`);
      }
    }

    const text = await response.text().catch(() => '');
    console.error(`Zero Day: ${who} returned ${response.status}`, text);
    let reason = text;
    try { reason = JSON.parse(text).error.message || text; } catch { /* keep raw text */ }

    if (RETRY_STATUSES.has(response.status) && attempt < MAX_RETRIES) {
      setStatus(attempt === 0 ? 'The safety checker is busy. Trying again…' : 'Still busy. One last try…');
      await delay(1500 * (attempt + 1));
      continue;
    }
    throw new ScanError(errorCodeForStatus(response.status, String(reason)),
      `${who} returned ${response.status}: ${String(reason).slice(0, 300)}`, response.status);
  }
}

// ===== OPTION 1: YOUR SERVER (recommended) =====
// `payload` is already cleaned of personal details: { host, url, title, text, links }.
// Your server adds the Gemini key and instructions, then returns the verdict JSON above.
async function callScanProxy(payload) {
  return postJson(SCAN_PROXY_URL, {}, { payload }, 'the scan server');
}

// ===== OPTION 2: STRAIGHT TO GEMINI (development) =====
// Uses GEMINI_API_KEY, GEMINI_SYSTEM_PROMPT and GEMINI_RESPONSE_SCHEMA from config.js.
async function callGemini(payload) {
  const data = await postJson(GEMINI_ENDPOINT, { 'x-goog-api-key': GEMINI_API_KEY }, {
    systemInstruction: { parts: [{ text: GEMINI_SYSTEM_PROMPT }] },
    contents: [{ role: 'user', parts: [{ text: JSON.stringify(payload) }] }],
    generationConfig: {
      responseMimeType: 'application/json',
      responseSchema: GEMINI_RESPONSE_SCHEMA,
      temperature: 0.2
    }
  }, 'Gemini');
  const parts = data && data.candidates && data.candidates[0] && data.candidates[0].content
    ? data.candidates[0].content.parts : null;
  const text = (parts || []).map((part) => part.text || '').join('');
  if (!text) {
    console.error('Zero Day: Gemini sent no text', data);
    const why = data && data.promptFeedback && data.promptFeedback.blockReason;
    throw new ScanError('bad-answer', `Gemini sent back no answer${why ? ' (blocked: ' + why + ')' : ''}`);
  }
  return parseVerdictJson(text);
}

const DEFAULT_SCORES = { safe: 10, caution: 50, danger: 90 };
const HEADLINES = {
  safe: 'This page looks okay',
  caution: 'Be careful on this page',
  danger: 'This page shows strong warning signs'
};

// Safe-guards for whatever comes back: clamps the score, fills in gaps.
function normalizeVerdict(raw) {
  if (!raw || typeof raw !== 'object') throw new ScanError('bad-answer', 'The answer was not an object');
  // Pages Chrome won't let us read: not scanned, shown as 0%.
  if (raw.noScan) {
    return { score: 0, level: 'info', headline: raw.headline, noScan: true,
      explanation: raw.verdict, actions: raw.action_items };
  }
  const given = String(raw.threat_level || '').toLowerCase();
  const number = Math.round(Number(raw.meter_score));
  const score = Number.isFinite(number)
    ? Math.min(100, Math.max(1, number))
    : (DEFAULT_SCORES[given] || 50);
  return {
    score,
    level: ['safe', 'caution', 'danger'].includes(given) ? given : levelFromScore(score),
    explanation: String(raw.verdict || ''),
    actions: Array.isArray(raw.action_items) ? raw.action_items.map(String).slice(0, 4) : []
  };
}

// ---- DEMO ONLY: runs when no scan service is set up in config.js ----
// Counts a few common scam phrases so you can see every meter state.
// Returns the same shape the real service returns.
function mockVerdict(payload) {
  const phrases = ['verify your account', 'urgent', 'act now', 'gift card', 'suspended', 'wire transfer',
    'your computer is infected', 'call this number', 'limited time', 'you have won', 'social security',
    'bitcoin', 'confirm your password', 'final notice'];
  const haystack = `${payload.title} ${payload.text}`.toLowerCase();
  const hits = phrases.filter((phrase) => haystack.includes(phrase)).length;
  // Phrases plus the same warning signs shown under "What we noticed".
  const signs = detectFindings({ title: payload.title, text: payload.text, links: payload.links }).length;
  const score = Math.min(100, 8 + hits * 12 + signs * 20);
  const level = levelFromScore(score);

  const copy = {
    safe: {
      verdict: "We didn't spot the usual warning signs on this page. It's still a good habit to stay careful about what you type in.",
      action_items: [
        'You can keep browsing as normal.',
        "If a page ever asks for a password or card number you weren't expecting, come back and scan it."
      ]
    },
    caution: {
      verdict: "A few things here are common in scams, like pressure to act fast or requests for personal details. That doesn't mean it's fake, but it's worth slowing down.",
      action_items: [
        "Don't enter passwords or card numbers yet.",
        "Visit the company's website by typing its address yourself, instead of using links on this page.",
        "Ask someone you trust to take a look if you're unsure."
      ]
    },
    danger: {
      verdict: "This page looks a lot like a scam. It's best to leave without clicking anything else. You haven't done anything wrong by checking.",
      action_items: [
        'Close this tab.',
        "Don't call phone numbers or download files from this page.",
        'If you already typed a password, change it on the real website and turn on two-step sign-in.'
      ]
    }
  }[level];

  return { threat_level: level.toUpperCase(), meter_score: score, ...copy, isMock: true };
}

/* ---------------------------------------------------------------------
   8. THREAT ASSESSMENT SCREEN
   The percent chance of a threat is shown in five color bands:
   1 very low (green), 2 low, 3 moderate, 4 high, 5 very high (red).
   --------------------------------------------------------------------- */

const BAND_WORDS = ['Very low', 'Low', 'Moderate', 'High', 'Very high'];

function levelFromScore(score) {
  return score < 34 ? 'safe' : score < 67 ? 'caution' : 'danger';
}

// 1-20 -> 1, 21-40 -> 2, 41-60 -> 3, 61-80 -> 4, 81-100 -> 5
function bandFromScore(score) {
  return Math.min(5, Math.max(1, Math.ceil(score / 20)));
}

function renderFindings(findings) {
  $('#findings').hidden = findings.length === 0;
  $('#finding-list').replaceChildren(...findings.map((finding) => {
    const card = el('button', `finding-card kind-${finding.kind}`);
    card.type = 'button';
    card.setAttribute('aria-pressed', 'false');
    card.append(el('strong', '', finding.title), el('span', 'finding-detail', finding.detail));
    card.addEventListener('click', () => markFindings([finding], card));
    return card;
  }));
  $('#clear-button').hidden = true;
  $('#mark-status').textContent = '';
}

function renderResults(raw, host, findings) {
  const verdict = normalizeVerdict(raw);
  const noScan = Boolean(verdict.noScan);
  const band = noScan ? 'none' : bandFromScore(verdict.score);
  const risk = noScan ? 'Not scanned' : `${BAND_WORDS[band - 1]} risk`;

  // Only point at specific findings when the overall verdict isn't "safe",
  // so a calm page isn't covered in warnings.
  currentFindings = noScan || verdict.level === 'safe' ? [] : findings;

  $('#percent').dataset.band = String(band);
  $('#percent-number').textContent = `${verdict.score}%`;
  $('#percent-caption').textContent = noScan ? 'nothing was checked' : 'chance of a threat';

  const meter = $('#meter');
  meter.dataset.band = String(band);
  meter.setAttribute('aria-label', noScan ? 'Threat meter: page not scanned' : `Threat meter: ${verdict.score} percent chance of a threat. ${risk}.`);
  const fill = $('#meter-fill');
  fill.style.width = '0%';

  const count = currentFindings.length;
  $('#risk-line').textContent = noScan ? 'Not scanned' : count
    ? `${risk} \u2022 ${count} warning ${count === 1 ? 'sign' : 'signs'} found`
    : `${risk}`;

  $('#verdict-headline').textContent = verdict.headline || HEADLINES[verdict.level];
  $('#verdict-explainer').textContent = verdict.explanation;
  $('#scanned-host').textContent = host ? `Page checked: ${host}` : '';
  $('#demo-note').hidden = !raw.isMock;
  $('#verdict').className = `verdict level-${verdict.level}`;

  renderFindings(currentFindings);

  $('#action-list').replaceChildren(...verdict.actions.map((action) => {
    const item = el('li');
    item.append(el('span', 'tick'), el('span', '', action));
    return item;
  }));

  homeView.hidden = true;
  resultsView.hidden = false;
  $('.app-main').scrollTop = 0;
  // Next frame, so the bar visibly slides to its answer.
  requestAnimationFrame(() => {
    // Stretch the green-to-red gradient across the whole track, so the bar
    // only reveals as much of it as the score reaches.
    fill.style.backgroundSize = `${10000 / Math.max(verdict.score, 1)}% 100%`;
    fill.style.width = `${verdict.score}%`;
  });
}

/* ---------------------------------------------------------------------
   9. LATEST ALERTS FEED
   ---------------------------------------------------------------------
   Backend contract for THREAT_FEED_URL. Return JSON like:
   { "items": [ {
        "id": "unique-string",
        "title": "Plain-English headline",
        "summary": "1-2 calm sentences about what's happening",
        "severity": "high" | "medium" | "low",   // groups: Act today / Act this week / Good to know (most urgent shown first)
        "published": "2026-11-04T12:00:00Z",
        "actions": ["Short step 1", "Short step 2"],
        "sourceName": "Bleeping Computer",
        "sourceUrl": "https://..."               // link to the related article
   } ] }
   The server (not this extension) should do the filtering: keep only stories
   an everyday person can act on, and drop foreign breaches and corporate-only
   attacks. Rewrite headlines and steps in the same calm, simple tone.
   --------------------------------------------------------------------- */

let currentAlerts = [];

function buildSampleThreats() {
  const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString();
  return [
    {
      id: 'sample-1', severity: 'high', published: daysAgo(1),
      title: 'Fake package-delivery texts are going around',
      summary: 'Scammers are texting that a package is waiting and asking you to tap a link to reschedule. The link leads to a fake page that collects your details.',
      actions: [
        "Don't tap links in texts you weren't expecting.",
        "Check on a delivery by typing the carrier's website address yourself.",
        'Delete the message. You can also forward it to 7726 to report it as spam.'
      ],
      sourceName: 'Bleeping Computer', sourceUrl: 'https://www.bleepingcomputer.com/'
    },
    {
      id: 'sample-2', severity: 'medium', published: daysAgo(3),
      title: 'A browser add-on was caught copying saved passwords',
      summary: 'Some free add-ons that looked helpful were found sending saved passwords to strangers. If you have add-ons you do not remember installing, it is worth a look.',
      actions: [
        'Click the puzzle-piece icon at the top of Chrome, then choose Manage extensions.',
        "Remove any add-on you don't recognize or no longer use.",
        'If you removed one, change the passwords you use most and turn on two-step sign-in.'
      ],
      sourceName: 'Krebs on Security', sourceUrl: 'https://krebsonsecurity.com/'
    },
    {
      id: 'sample-3', severity: 'high', published: daysAgo(5),
      title: 'Pop-ups claiming your computer is infected',
      summary: 'A loud pop-up says your computer has a virus and gives a phone number to call. The number connects you to scammers who ask for payment or remote access.',
      actions: [
        'Close the tab or window. Do not call the number.',
        'If the pop-up will not close, restart your browser.',
        'If someone already got access to your computer, turn it off and call your bank.'
      ],
      sourceName: 'Bleeping Computer', sourceUrl: 'https://www.bleepingcomputer.com/'
    },
    {
      id: 'sample-4', severity: 'low', published: daysAgo(8),
      title: 'Chrome has a security update ready',
      summary: 'A new version of Chrome fixes problems that attackers could use. Updates install quickly and your tabs come back after restarting.',
      actions: [
        'Click the three dots at the top right, then Help, then About Google Chrome.',
        'Wait for the update, then choose Relaunch.'
      ],
      sourceName: 'Bleeping Computer', sourceUrl: 'https://www.bleepingcomputer.com/'
    }
  ];
}

// ===== PLUG THE THREAT FEED IN HERE =====
async function fetchLatestThreats() {
  if (!THREAT_FEED_URL) return { isSample: true, items: buildSampleThreats() };

  const response = await fetch(THREAT_FEED_URL, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`Feed returned ${response.status}`);
  const data = await response.json();
  return { isSample: false, items: Array.isArray(data.items) ? data.items : [] };
}

// Most urgent first. Anything unrecognized is treated as "low".
const SEVERITY_ORDER = ['high', 'medium', 'low'];
const SEVERITY_LABELS = {
  high:   { text: 'Act today',     hint: 'Worth doing as soon as you can.' },
  medium: { text: 'Act this week', hint: 'Do these in the next few days.' },
  low:    { text: 'Good to know',  hint: 'No rush, but helpful to keep in mind.' }
};
const severityOf = (item) => (SEVERITY_ORDER.includes(item.severity) ? item.severity : 'low');

// Order by severity, then newest first inside each group.
function sortBySeverity(items) {
  return [...items].sort((a, b) =>
    SEVERITY_ORDER.indexOf(severityOf(a)) - SEVERITY_ORDER.indexOf(severityOf(b)) ||
    new Date(b.published) - new Date(a.published));
}

// Alerts the person has ticked as done (saved on this computer).
let archivedIds = new Set();

async function loadAlerts() {
  const message = $('#alerts-message');
  try {
    const { archivedAlerts = [] } = await chrome.storage.local.get('archivedAlerts');
    archivedIds = new Set(archivedAlerts);
    const { isSample, items } = await fetchLatestThreats();
    currentAlerts = items;
    $('#sample-note').hidden = !isSample;
    renderAlerts(items);
    await updateAlertsBadge(items);
  } catch (error) {
    console.error('Zero Day: could not load alerts', error);
    message.textContent = "We couldn't load the alerts just now. Check your internet connection and open this tab again in a little while.";
    message.hidden = false;
  }
}

// Builds one alert card. Finished alerts get a short version for the Done list.
function buildAlertCard(item, done = false) {
  const level = severityOf(item);
  const card = el('article', `alert sev-${level}${done ? ' is-done' : ''}`);
  card.dataset.alertId = item.id;

  const date = new Date(item.published).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  card.append(el('p', 'alert-meta', [date, item.sourceName].filter(Boolean).join(' · ')));
  card.append(el('h4', 'alert-title', item.title));

  if (!done) {
    card.append(el('p', '', item.summary));
    const steps = el('ul', 'actions');
    (item.actions || []).forEach((action) => {
      const step = el('li');
      step.append(el('span', 'tick'), el('span', '', action));
      steps.append(step);
    });
    card.append(el('p', 'alert-steps-label', 'What to do'), steps);
  }

  const foot = el('div', 'alert-foot');
  const href = safeUrl(item.sourceUrl);
  if (href) {
    const link = el('a', 'text-link', done ? 'Read the story again' : `Read the full story${item.sourceName ? ' at ' + item.sourceName : ''}`);
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    foot.append(link);
  }
  const label = el('label', 'done-check');
  const box = el('input');
  box.type = 'checkbox';
  box.checked = done;
  box.addEventListener('change', () => setAlertDone(item.id, box.checked));
  label.append(box, el('span', '', done ? 'Done. Untick to bring it back' : 'I took care of this'));
  foot.append(label);
  card.append(foot);
  return card;
}

// Ticking the box moves an alert to the Done list; unticking brings it back.
async function setAlertDone(id, done) {
  if (done) archivedIds.add(id); else archivedIds.delete(id);
  await chrome.storage.local.set({ archivedAlerts: Array.from(archivedIds) });
  renderAlerts(currentAlerts);
  updateAlertsBadge(currentAlerts);
  $('#alerts-live').textContent = done ? 'Alert moved to the Done list.' : 'Alert moved back to your alerts.';
  const target = done
    ? $('#archive-summary')
    : document.querySelector(`#alert-list [data-alert-id="${CSS.escape(id)}"] input`);
  if (target) target.focus();
}

// Open alerts are grouped under "Act today", "Act this week" and "Good to know".
// Finished ones go to the Done list at the bottom.
function renderAlerts(items) {
  const open = sortBySeverity(items.filter((item) => !archivedIds.has(item.id)));
  const done = items
    .filter((item) => archivedIds.has(item.id))
    .sort((a, b) => new Date(b.published) - new Date(a.published));

  const sections = [];
  SEVERITY_ORDER.forEach((level) => {
    const group = open.filter((item) => severityOf(item) === level);
    if (!group.length) return;
    const info = SEVERITY_LABELS[level];
    const heading = el('h3', 'alert-group-title');
    heading.append(el('span', '', info.text), el('span', 'alert-count', `${group.length} ${group.length === 1 ? 'alert' : 'alerts'}`));
    const section = el('section', `alert-group group-${level}`);
    section.append(heading, el('p', 'alert-group-hint', info.hint), ...group.map((item) => buildAlertCard(item)));
    sections.push(section);
  });
  $('#alert-list').replaceChildren(...sections);

  const message = $('#alerts-message');
  if (!items.length) {
    message.textContent = 'There are no new alerts right now. When something comes up that you should know about, it will show here.';
  } else if (!open.length) {
    message.textContent = "You're all caught up. Alerts you've finished are in the Done list below.";
  }
  message.hidden = open.length > 0;

  $('#alert-archive').hidden = done.length === 0;
  $('#archive-summary').textContent = `Done (${done.length})`;
  $('#archive-list').replaceChildren(...done.map((item) => buildAlertCard(item, true)));
}

// A small count on the Alerts tab for alerts the person hasn't opened yet.
async function updateAlertsBadge(items) {
  const { seenAlertIds = [] } = await chrome.storage.local.get('seenAlertIds');
  const unseen = items.filter((item) => !seenAlertIds.includes(item.id) && !archivedIds.has(item.id)).length;
  const badge = $('#alerts-badge');
  badge.textContent = String(unseen);
  badge.hidden = unseen === 0;
  $('#tab-alerts').setAttribute('aria-label', unseen ? `Alerts, ${unseen} new` : 'Alerts');
}

function markAlertsSeen() {
  if (!currentAlerts.length) return;
  chrome.storage.local.set({ seenAlertIds: currentAlerts.map((item) => item.id) });
  $('#alerts-badge').hidden = true;
  $('#tab-alerts').setAttribute('aria-label', 'Alerts');
}

/* ---------------------------------------------------------------------
   10. OPTIONAL NEWSLETTER
   Never required. The Alerts tab works the same whether or not someone signs up.
   --------------------------------------------------------------------- */

// ===== PLUG THE NEWSLETTER SERVICE IN HERE =====
async function subscribeToNewsletter(email) {
  if (!NEWSLETTER_URL) return; // demo: nothing is sent
  const response = await fetch(NEWSLETTER_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  if (!response.ok) throw new Error(`Newsletter returned ${response.status}`);
}

async function unsubscribeFromNewsletter(email) {
  if (!NEWSLETTER_URL) return;
  await fetch(NEWSLETTER_URL, {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
}

function renderNewsletter(email) {
  $('#newsletter-form').hidden = Boolean(email);
  $('#newsletter-done').hidden = !email;
  if (email) $('#newsletter-done-text').textContent = `You're signed up with ${email}. You can stop the emails any time.`;
}

$('#newsletter-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const input = $('#newsletter-email');
  const message = $('#newsletter-message');
  const email = input.value.trim();
  if (!input.checkValidity()) {
    message.textContent = 'Please check the email address. It should look like name@example.com.';
    return;
  }
  try {
    await subscribeToNewsletter(email);
    await chrome.storage.local.set({ newsletterEmail: email });
    renderNewsletter(email);
    message.textContent = NEWSLETTER_URL ? '' : 'Demo only: your address is saved on this computer, and no emails will be sent yet.';
  } catch (error) {
    console.error('Zero Day: newsletter sign-up failed', error);
    message.textContent = "We couldn't sign you up just now. Please try again later.";
  }
});

$('#newsletter-stop').addEventListener('click', async () => {
  const { newsletterEmail } = await chrome.storage.local.get('newsletterEmail');
  try { await unsubscribeFromNewsletter(newsletterEmail); } catch (error) { console.error(error); }
  await chrome.storage.local.remove('newsletterEmail');
  renderNewsletter('');
  $('#newsletter-form').reset();
  $('#newsletter-message').textContent = "You won't get any more emails.";
});

/* ---------------------------------------------------------------------
   11. COMMUNITY STORIES (forum mockup)
   --------------------------------------------------------------------- */

let posts = [];

function buildSamplePosts() {
  const daysAgo = (n) => Date.now() - n * 86400000;
  return [
    { id: 's1', name: 'Margaret', topic: 'Phone call', created: daysAgo(2), same: 14,
      title: 'A caller said my bank account was frozen',
      body: 'He sounded very official and wanted me to read him a code from a text. I hung up and called the number on my card instead. The bank said nothing was wrong.' },
    { id: 's2', name: 'Dev', topic: 'Email', created: daysAgo(4), same: 9,
      title: 'Email said I owed money for a subscription I never bought',
      body: 'It had a big button to "cancel". I did not click it, and I checked my statement. There was no charge. Deleting it felt good.' },
    { id: 's3', name: 'Tom', topic: 'Website or pop-up', created: daysAgo(6), same: 21,
      title: 'Pop-up with a loud alarm sound',
      body: 'It said my computer was locked. Closing the whole browser fixed it. I was glad I did not call the number on the screen.' }
  ];
}

// ===== PLUG THE COMMUNITY SERVICE IN HERE =====
// A real forum needs moderation and abuse reporting on the server. Until then,
// posts live in chrome.storage.local on this computer only.
async function submitCommunityPost(post) {
  if (!COMMUNITY_URL) return;
  const response = await fetch(COMMUNITY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(post)
  });
  if (!response.ok) throw new Error(`Community returned ${response.status}`);
}

function timeAgo(timestamp) {
  const minutes = Math.round((Date.now() - timestamp) / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

function renderPosts() {
  $('#post-list').replaceChildren(...posts.map((post) => {
    const card = el('article', 'post');

    const head = el('div', 'post-head');
    const who = el('div');
    const when = `${post.topic}, ${timeAgo(post.created)}${post.mine ? ' · Your story' : ''}`;
    who.append(el('strong', '', post.name), el('span', '', when));
    const avatar = el('span', post.anonymous ? 'avatar avatar-anon' : 'avatar', post.anonymous ? '?' : post.name.charAt(0).toUpperCase());
    avatar.setAttribute('aria-hidden', 'true');
    head.append(avatar, who);

    const same = el('button', 'same-button', `This happened to me too (${post.same})`);
    same.type = 'button';
    same.setAttribute('aria-pressed', 'false');
    same.addEventListener('click', () => {
      const pressed = same.getAttribute('aria-pressed') === 'true';
      same.setAttribute('aria-pressed', String(!pressed));
      same.textContent = `This happened to me too (${post.same + (pressed ? 0 : 1)})`;
    });

    card.append(head, el('h3', '', post.title), el('p', '', post.body), same);
    return card;
  }));
}

async function loadCommunity() {
  const { myPosts = [] } = await chrome.storage.local.get('myPosts');
  posts = [...myPosts, ...buildSamplePosts()];
  renderPosts();
}

// "Post anonymously" is on by default. Turning it off lets the person add a name to show.
function syncAnonymous() {
  const anonymous = $('#post-anon').checked;
  $('#post-name').disabled = anonymous;
  if (anonymous) $('#post-name').value = '';
}
$('#post-anon').addEventListener('change', syncAnonymous);
syncAnonymous();

$('#post-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = $('#post-message');
  const rawBody = $('#post-text').value.trim();
  if (rawBody.length < 10) {
    message.textContent = 'Please write a little more so others can learn from your story.';
    return;
  }

  // Same sanitizer as page scans: hide emails, phone numbers and addresses.
  const report = {};
  const anonymous = $('#post-anon').checked;
  const typedName = sanitizePII($('#post-name').value.trim(), report).slice(0, 30);
  // An anonymous post carries no name at all, not even a hidden one.
  const post = {
    id: crypto.randomUUID(),
    anonymous,
    name: anonymous ? 'Anonymous' : (typedName || 'A community member'),
    topic: $('#post-topic').value,
    title: sanitizePII($('#post-title').value.trim(), report),
    body: sanitizePII(rawBody, report),
    created: Date.now(),
    same: 0
  };

  try {
    await submitCommunityPost(post);             // what the community service receives
    const mine = { ...post, mine: true };        // "mine" stays on this computer
    const { myPosts = [] } = await chrome.storage.local.get('myPosts');
    await chrome.storage.local.set({ myPosts: [mine, ...myPosts].slice(0, 20) });
    posts.unshift(mine);
    renderPosts();
    $('#post-form').reset();
    syncAnonymous();
    const hidden = Object.keys(report).length > 0;
    message.textContent = (anonymous ? 'Thank you for sharing. Your story was posted without your name.' : 'Thank you for sharing your story.') +
      (hidden ? ' Some personal details were hidden automatically.' : '');
  } catch (error) {
    console.error('Zero Day: could not share story', error);
    message.textContent = "We couldn't share your story just now. Please try again later.";
  }
});

/* ---------------------------------------------------------------------
   12. START-UP
   --------------------------------------------------------------------- */

initSettings();
loadAlerts();
loadCommunity();
chrome.storage.local.get('newsletterEmail').then(({ newsletterEmail }) => renderNewsletter(newsletterEmail || ''));
