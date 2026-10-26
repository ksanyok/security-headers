const WEIGHTS = { 'strict-transport-security': 25, 'content-security-policy': 25, 'x-content-type-options': 10, 'frame-protection': 15, 'referrer-policy': 10, 'permissions-policy': 10, 'cross-origin-opener-policy': 5 };

/** Parse a raw header block ("Name: value" lines) into a lowercase-keyed object; repeated headers are joined. */
export function parseHeaderBlock(text) {
  const out = {};
  for (const line of String(text).split(/\r?\n/)) {
    const m = /^([\w-]+):\s*(.*)$/.exec(line.trim());
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (k === 'set-cookie') (out[k] ||= []).push(m[2]);
    else out[k] = out[k] ? `${out[k]}, ${m[2]}` : m[2];
  }
  return out;
}

export function parseCsp(value) {
  const d = {};
  for (const part of String(value).split(';')) {
    const [name, ...vals] = part.trim().split(/\s+/);
    if (name) d[name.toLowerCase()] = vals;
  }
  return d;
}

/**
 * Grade a set of response headers.
 * @param {Record<string, string|string[]>} headers lowercase header names
 * @param {{https?: boolean}} [context]
 */
export function analyzeHeaders(headers, context = {}) {
  const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const issues = [];
  const add = (level, code, message) => issues.push({ level, code, message });
  const present = {};
  const https = context.https !== false;

  const hsts = h['strict-transport-security'];
  if (!https) add('info', 'hsts-http', 'HSTS is only honoured over HTTPS; the page was served over HTTP.');
  else if (!hsts) add('error', 'hsts-missing', 'Strict-Transport-Security is missing: browsers can be downgraded to HTTP on the first visit.');
  else {
    const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? -1);
    present['strict-transport-security'] = age >= 15552000 ? 1 : 0.5;
    if (age < 0) add('error', 'hsts-invalid', 'Strict-Transport-Security has no valid max-age.');
    else if (age < 15552000) add('warning', 'hsts-short', `HSTS max-age is ${age} seconds; use at least 6 months (15552000), ideally a year.`);
    if (!/includesubdomains/i.test(hsts)) add('info', 'hsts-subdomains', 'HSTS does not include subdomains.');
  }

  const csp = h['content-security-policy'];
  if (!csp) {
    if (h['content-security-policy-report-only']) add('warning', 'csp-report-only', 'Content-Security-Policy is in report-only mode and does not block anything yet.');
    else add('error', 'csp-missing', 'Content-Security-Policy is missing: no defence in depth against XSS and injected scripts.');
  } else {
    const d = parseCsp(csp);
    const scripts = d['script-src'] || d['default-src'];
    present['content-security-policy'] = 1;
    if (!scripts) { add('warning', 'csp-no-script-src', 'CSP has neither script-src nor default-src, so scripts are not restricted.'); present['content-security-policy'] = 0.5; }
    else {
      if (scripts.includes("'unsafe-inline'") && !scripts.some((s) => /^'(nonce-|sha\d{3}-|strict-dynamic)/.test(s))) { add('warning', 'csp-unsafe-inline', "CSP allows 'unsafe-inline' scripts, which removes most XSS protection."); present['content-security-policy'] = 0.5; }
      if (scripts.includes("'unsafe-eval'")) add('warning', 'csp-unsafe-eval', "CSP allows 'unsafe-eval'.");
      if (scripts.includes('*') || scripts.includes('https:') || scripts.includes('http:')) { add('warning', 'csp-wildcard', 'CSP allows scripts from any host.'); present['content-security-policy'] = 0.5; }
    }
    if (!d['object-src'] && !(d['default-src'] || []).includes("'none'")) add('info', 'csp-object-src', "Consider object-src 'none'.");
  }

  if ((h['x-content-type-options'] || '').toLowerCase().trim() === 'nosniff') present['x-content-type-options'] = 1;
  else add('warning', 'nosniff-missing', 'X-Content-Type-Options: nosniff is missing.');

  const fa = csp && parseCsp(csp)['frame-ancestors'];
  const xfo = (h['x-frame-options'] || '').toUpperCase();
  if (fa || ['DENY', 'SAMEORIGIN'].includes(xfo.trim())) present['frame-protection'] = 1;
  else add('warning', 'clickjacking', 'Neither X-Frame-Options nor CSP frame-ancestors is set: the page can be framed (clickjacking).');

  const rp = (h['referrer-policy'] || '').toLowerCase();
  if (!rp) add('warning', 'referrer-missing', 'Referrer-Policy is missing (browsers default to strict-origin-when-cross-origin).');
  else if (/unsafe-url|^no-referrer-when-downgrade$/.test(rp.split(',').pop().trim())) add('warning', 'referrer-leaky', `Referrer-Policy "${rp}" leaks full URLs to other sites.`);
  else present['referrer-policy'] = 1;

  if (h['permissions-policy']) present['permissions-policy'] = 1;
  else add('info', 'permissions-missing', 'Permissions-Policy is missing (camera, microphone, geolocation… are not restricted).');
  if (h['cross-origin-opener-policy']) present['cross-origin-opener-policy'] = 1;
  else add('info', 'coop-missing', 'Cross-Origin-Opener-Policy is missing.');

  if (h['x-powered-by']) add('info', 'x-powered-by', `X-Powered-By reveals "${h['x-powered-by']}".`);
  if (/\d/.test(h.server || '')) add('info', 'server-version', `Server header reveals a version: "${h.server}".`);
  if (h['x-xss-protection'] && !/^0/.test(h['x-xss-protection'])) add('info', 'x-xss-protection', 'X-XSS-Protection is deprecated; set it to 0 or remove it and rely on CSP.');

  const cookies = [].concat(h['set-cookie'] || []);
  for (const ck of cookies) {
    const name = ck.split('=')[0].trim();
    const flags = ck.toLowerCase();
    const missing = [https && !/;\s*secure/.test(flags) && 'Secure', !/;\s*httponly/.test(flags) && 'HttpOnly', !/;\s*samesite/.test(flags) && 'SameSite'].filter(Boolean);
    if (missing.length) add('warning', 'cookie-flags', `Cookie "${name}" is missing ${missing.join(', ')}.`);
  }

  const max = Object.values(WEIGHTS).reduce((a, b) => a + b, 0) - (https ? 0 : WEIGHTS['strict-transport-security']);
  const got = Object.entries(present).reduce((s, [k, v]) => s + WEIGHTS[k] * v, 0);
  const score = Math.round((got / max) * 100);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : score >= 20 ? 'E' : 'F';
  return { score, grade, issues };
}
