# Getting started

## Requirements

Node.js 18 or newer. No other dependencies.

## Install

```bash
# one-off run
npx github:ksanyok/security-headers example.com

# global CLI
npm install -g github:ksanyok/security-headers

# as a library in your project
npm install github:ksanyok/security-headers
```

## First run

```bash
security-headers example.com
```

The first lines show the final URL after redirects and the grade with its score. Then each finding: `✖` a key protection is missing, `!` a protection is weak or a cookie lacks flags, `i` optional hardening or information leaks. With `--min` the exit code is 1 when the grade is below the threshold.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No errors (warnings allowed unless `--strict`) |
| 1 | Errors found (or warnings with `--strict`) |
| 2 | Bad arguments or the check could not run |

## More examples

**Fail if the grade drops below B**

```bash
security-headers https://example.com --min B
```

**Analyse headers you already have (no request from this tool)**

```bash
curl -sI https://example.com | security-headers --stdin
```

**See every response header**

```bash
security-headers example.com --show-headers
```

## Without installing anything

Use the [online Security Headers Checker](https://promopilot.link/en/tools/security-headers.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=security-headers).
