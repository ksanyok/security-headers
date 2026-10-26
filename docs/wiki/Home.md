# Security Headers Checker

`security-headers` fetches a page and grades the HTTP response headers browsers use to protect your visitors: HSTS, Content-Security-Policy (including whether it actually restricts scripts), `X-Content-Type-Options`, clickjacking protection via `X-Frame-Options` or `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`. It also checks cookie flags and headers that reveal server versions, and turns everything into a score from 0 to 100 and a grade from A to F you can enforce in CI.

- **[Getting started](Getting-Started)** — install, first run, reading the output
- **[FAQ](FAQ)** — common questions
- **[Troubleshooting](Troubleshooting)** — errors and how to fix them

Prefer a browser? The same check runs online at **[PromoPilot](https://promopilot.link/en/tools/security-headers.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=security-headers)** — free, no sign-up.
