import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeHeaders, parseHeaderBlock, parseCsp, checkSecurityHeaders } from '../src/index.js';

const STRONG = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
  'cross-origin-opener-policy': 'same-origin',
};
const codes = (r) => r.issues.map((i) => i.code);

test('strong headers get an A with no issues', () => {
  const r = analyzeHeaders(STRONG);
  assert.equal(r.grade, 'A');
  assert.equal(r.score, 100);
  assert.deepEqual(r.issues, []);
});

test('no headers get an F', () => {
  const r = analyzeHeaders({});
  assert.equal(r.grade, 'F');
  for (const code of ['hsts-missing', 'csp-missing', 'nosniff-missing', 'clickjacking', 'referrer-missing']) assert.ok(codes(r).includes(code), code);
});

test('weak CSP and HSTS lower the score', () => {
  const r = analyzeHeaders({ ...STRONG, 'strict-transport-security': 'max-age=300', 'content-security-policy': "script-src * 'unsafe-inline' 'unsafe-eval'" });
  for (const code of ['hsts-short', 'hsts-subdomains', 'csp-unsafe-inline', 'csp-unsafe-eval', 'csp-wildcard']) assert.ok(codes(r).includes(code), code);
  assert.ok(r.score < 100);
});

test('nonces make unsafe-inline acceptable', () => {
  const r = analyzeHeaders({ ...STRONG, 'content-security-policy': "script-src 'self' 'unsafe-inline' 'nonce-xyz'; object-src 'none'; frame-ancestors 'self'" });
  assert.ok(!codes(r).includes('csp-unsafe-inline'));
});

test('cookies, leaks and legacy headers', () => {
  const r = analyzeHeaders({ ...STRONG, server: 'nginx/1.18.0', 'x-powered-by': 'PHP/8.1', 'x-xss-protection': '1; mode=block', 'set-cookie': ['sid=1; Path=/', 'ok=1; Secure; HttpOnly; SameSite=Lax'] });
  for (const code of ['server-version', 'x-powered-by', 'x-xss-protection']) assert.ok(codes(r).includes(code), code);
  assert.equal(r.issues.filter((i) => i.code === 'cookie-flags').length, 1);
});

test('HTTP pages are not penalised for HSTS', () => {
  const r = analyzeHeaders({ ...STRONG, 'strict-transport-security': undefined }, { https: false });
  assert.ok(codes(r).includes('hsts-http'));
  assert.equal(r.grade, 'A');
});

test('parses raw header blocks and CSP', () => {
  const h = parseHeaderBlock('HTTP/2 200\r\nX-Frame-Options: DENY\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n');
  assert.equal(h['x-frame-options'], 'DENY');
  assert.deepEqual(h['set-cookie'], ['a=1', 'b=2']);
  assert.deepEqual(parseCsp("default-src 'self'; img-src *")['img-src'], ['*']);
});

test('fetches and grades a URL', async () => {
  const r = await checkSecurityHeaders('example.com', { fetch: async (url) => new Response('ok', { status: 200, headers: STRONG }) });
  assert.equal(r.url, 'https://example.com/');
  assert.equal(r.grade, 'A');
});
