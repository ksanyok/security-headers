import { analyzeHeaders } from './analyze.js';

export { analyzeHeaders, parseHeaderBlock, parseCsp } from './analyze.js';

/**
 * Fetch a URL (following redirects) and grade its security headers.
 * @param {string} url
 * @param {{fetch?: typeof fetch, userAgent?: string}} [options]
 */
export async function checkSecurityHeaders(url, options = {}) {
  const doFetch = options.fetch || globalThis.fetch;
  const start = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`).toString();
  const res = await doFetch(start, { redirect: 'follow', headers: { 'user-agent': options.userAgent || 'Mozilla/5.0 (compatible; security-headers; +https://github.com/ksanyok/security-headers)' } });
  const headers = {};
  res.headers.forEach((v, k) => { if (k !== 'set-cookie') headers[k] = v; });
  const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  if (cookies.length) headers['set-cookie'] = cookies;
  const finalUrl = res.url || start;
  return { url: start, finalUrl, status: res.status, headers, ...analyzeHeaders(headers, { https: finalUrl.startsWith('https:') }) };
}
