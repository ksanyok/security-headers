#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { checkSecurityHeaders, analyzeHeaders, parseHeaderBlock } from '../src/index.js';

const HELP = `Usage: security-headers <url> [options]
       curl -sI https://example.com | security-headers --stdin

Fetches a page and grades its HTTP security headers (HSTS, CSP,
X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy,
COOP) plus cookie flags and information leaks. Score 0-100, grade A-F.

Options:
  --stdin           Analyse a raw header block from standard input
  --file <path>     Analyse a raw header block from a file
  --min <grade>     Exit with code 1 if the grade is below this (e.g. B)
  --show-headers    Print all response headers
  --json            Print JSON
  -h, --help        Show this help

Online version (no install): https://promopilot.link/en/tools/security-headers.php?utm_source=github&utm_medium=cli&utm_campaign=tools&utm_content=security-headers
`;

const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const value = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
if (!args.length || flag('-h') || flag('--help')) { process.stdout.write(HELP); process.exit(args.length ? 0 : 2); }

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const ICON = { error: c(31, '✖'), warning: c(33, '!'), info: c(36, 'i') };
const GRADE_COLOR = { A: 32, B: 32, C: 33, D: 33, E: 31, F: 31 };
const valued = new Set(['--file', '--min']);

try {
  let report;
  if (flag('--stdin') || value('--file')) {
    const headers = parseHeaderBlock(readFileSync(value('--file') || 0, 'utf8'));
    report = { source: value('--file') || 'stdin', headers, ...analyzeHeaders(headers) };
  } else {
    report = await checkSecurityHeaders(args.find((a, i) => !a.startsWith('-') && !valued.has(args[i - 1])));
  }
  if (flag('--json')) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`${c(1, 'URL:')}   ${report.finalUrl || report.source}${report.status ? `  (HTTP ${report.status})` : ''}`);
    console.log(`${c(1, 'Grade:')} ${c(GRADE_COLOR[report.grade], `${report.grade}  ${report.score}/100`)}\n`);
    if (flag('--show-headers')) { for (const [k, v] of Object.entries(report.headers)) console.log(`  ${c(2, k)}: ${[].concat(v).join(' | ')}`); console.log(''); }
    if (!report.issues.length) console.log(c(32, '✔ All recommended security headers are set'));
    for (const i of report.issues) console.log(`  ${ICON[i.level]} ${i.message}`);
  }
  const min = (value('--min') || 'F').toUpperCase();
  process.exit('ABCDEF'.indexOf(report.grade) > 'ABCDEF'.indexOf(min) ? 1 : 0);
} catch (err) {
  console.error(c(31, `Error: ${err.message}`));
  process.exit(2);
}
