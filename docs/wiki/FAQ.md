# FAQ

## Which headers matter most?

HSTS and a real Content-Security-Policy give the most protection, followed by clickjacking protection and `X-Content-Type-Options: nosniff`. The others are cheap hardening.

## Is X-Frame-Options still needed?

CSP `frame-ancestors` supersedes it in modern browsers. Either one satisfies this check; sending both is harmless.

## How do I add a CSP without breaking my site?

Start with `Content-Security-Policy-Report-Only` and a `report-to` endpoint, fix what gets reported, then switch to the enforcing header. Use nonces or hashes instead of `'unsafe-inline'`.

## Should I remove X-XSS-Protection?

Yes, or set it to `0`. The browser XSS auditor it controlled has been removed and could itself introduce vulnerabilities.

## Why is my grade different from other scanners?

Weights and rules differ between tools. This one rewards headers that actually restrict behaviour (an enforcing CSP that limits scripts) rather than their mere presence.
