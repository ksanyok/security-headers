# Troubleshooting

## Headers I set are not detected

A CDN, load balancer or the framework may overwrite or strip them, or they are only set on some routes. Check the exact URL with `--show-headers`, and remember redirects are followed — the final response is graded.

## Different results for www and bare domain

They are often served by different configurations. Check both, and the redirect between them.

## Request blocked (403/429)

Use `curl -sI` with your own options and pipe it into `--stdin`.

## Still stuck?

Open an [issue](https://github.com/ksanyok/security-headers/issues/new/choose) with the command, the output (`--json` if possible) and your Node.js version — or compare with the [online version](https://promopilot.link/en/tools/security-headers.php?utm_source=github&utm_medium=repo&utm_campaign=tools&utm_content=security-headers).
