# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-26

### Added
- `security-headers` CLI with A-F grade, `--min` threshold, `--show-headers`, `--json`, and offline analysis from `--stdin` or `--file`
- Weighted scoring for HSTS, CSP, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy and COOP
- CSP quality checks: unsafe-inline without nonces/hashes, unsafe-eval, wildcard sources, missing script-src, report-only mode
- Cookie flag checks (Secure, HttpOnly, SameSite) and information leaks (Server version, X-Powered-By, legacy X-XSS-Protection)
- Library API (`checkSecurityHeaders`, `analyzeHeaders`, `parseHeaderBlock`, `parseCsp`) and GitHub Action

[1.0.0]: https://github.com/ksanyok/security-headers/releases/tag/v1.0.0
