# header-grader

> Security header grader for **local dev** — grade your dev server's HTTP security headers and generate the exact Express/Nginx config that fixes them.

[![Node ≥ 18](https://img.shields.io/badge/node-%E2%89%A5%2018-brightgreen)](#requirements)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-blue)](#design-goals)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](#license)

```
  Grade: F  (13/100)  http://localhost:3000/

  ✗ Content-Security-Policy
    Missing. CSP is your strongest defense against XSS.
  ✗ X-Content-Type-Options
    Missing. Prevents MIME-type sniffing attacks.
  ✗ X-Frame-Options
    Missing (and no CSP frame-ancestors). Your site can be framed for clickjacking.
  ...

  Generate the fix: header-grader http://localhost:3000 --fix express
```

## Why this exists

Security headers are one of the highest-leverage, lowest-effort defenses in web development: a handful of response headers protect against XSS, clickjacking, MIME sniffing, protocol downgrade attacks, and cross-origin data leaks. Yet most projects ship without them — not because they're hard, but because nothing in the **development workflow** ever mentions them.

The existing tools all live at the wrong end of the pipeline:

- **[SecurityHeaders.com](https://securityheaders.com)** is excellent, but it scans public production URLs. It can't reach `localhost`, so you only find out after you deploy.
- **[Lighthouse](https://developer.chrome.com/docs/lighthouse)** proves the model this tool follows — automated, actionable audits against your local dev server — but security headers are a sidebar there. Its best-practices category includes a CSP-effectiveness check and a couple of related audits, and stops short of the full suite: no HSTS `max-age` grading, no Referrer-Policy, Permissions-Policy, or CORP checks, no flagging of `X-Powered-By`/`Server` version leaks — and no generated fix config. Lighthouse is to performance and accessibility what this tool aims to be for security headers.
- **Browser devtools** show you headers, but don't evaluate them or tell you what's missing.
- **Helmet's docs** tell you what to configure, but not what your app is *actually sending* after all your middleware runs.

By the time a production scanner flags the problem, the fix means a config change, a review, and a redeploy. The cheapest moment to fix a missing header is while the dev server is still running on your desk.

`header-grader` closes that gap with three ideas:

1. **Grade the dev server, not prod.** Point it at `localhost` while you're building.
2. **Don't just diagnose — generate the fix.** Every failing check maps to a concrete config snippet for Express (helmet) or Nginx. The snippet is a *minimal diff*: it only includes headers that are actually failing.
3. **Be dev-aware.** A production scanner would fail you for missing HSTS on `http://localhost:3000` — but browsers ignore HSTS over plain HTTP anyway. This tool knows the difference between "wrong" and "expected in dev, don't forget it in prod."

The project grew out of web development coursework: the same philosophy as accessibility auditing (Lighthouse, axe) applied to security headers — automated, actionable feedback inside the dev loop instead of after deployment.

## Requirements

- Node.js ≥ 18 (uses the built-in `fetch`)

## Installation

No install needed for one-off checks:

```sh
npx header-grader localhost:3000
```

For the middleware or repeated use, add it as a dev dependency:

```sh
npm install --save-dev header-grader
```

Or globally for a system-wide CLI:

```sh
npm install -g header-grader
```

> **Note:** until the package is published to npm, install from a local clone:
> ```sh
> git clone <repo-url> && cd header-grader
> npm install && npm run build && npm link   # makes `header-grader` available globally
> ```

## Usage

### 1. CLI — grade a running server

Start your dev server, then:

```sh
header-grader localhost:3000
```

You get a letter grade (A+ through F), a 0–100 score, and a per-header breakdown explaining what each missing header protects against.

**Generate the fix** for whatever failed:

```sh
header-grader localhost:3000 --fix express
```

```js
// npm install helmet
import helmet from "helmet";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"], // add CDN origins here as needed
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'self'"],
      },
    },
    ...
  })
);

// Stop advertising Express:
app.disable("x-powered-by");
```

Or for an Nginx reverse proxy:

```sh
header-grader localhost:3000 --fix nginx
```

```nginx
# Add inside your server {} block
add_header Content-Security-Policy "default-src 'self'; ..." always;
add_header X-Content-Type-Options "nosniff" always;
server_tokens off;
```

Apply the snippet, re-run the command, and watch the grade climb.

**Understand the stakes** — `--explain` adds a concrete attack scenario under every failing header:

```sh
header-grader localhost:3000 --explain
```

```
  ✗ X-Frame-Options
    Missing (and no CSP frame-ancestors). Your site can be framed for clickjacking.
    If exploited:
      Clickjacking: an attacker's page loads your site in an invisible
      full-screen iframe and positions a fake 'Play video' button exactly
      over your real 'Delete account' or 'Transfer funds' button. The victim
      clicks their page but presses yours — with their logged-in session.
```

This is the teaching half of the tool: not just *what's* missing, but what an attacker does with the gap — session theft via injected scripts (CSP), sslstrip downgrades on public Wi-Fi (HSTS), stored XSS through file uploads (nosniff), reset-token leaks through the Referer header (Referrer-Policy), and so on.

**All CLI options:**

| Option | Description |
| --- | --- |
| `--explain` | Show how each missing header could be exploited |
| `--fix <express\|nginx>` | Print a config snippet that fixes the failing headers |
| `--json` | Output the full report as JSON |
| `--min-grade <grade>` | Exit with code 1 if the grade is below this — for CI |
| `-h, --help` | Show help |

### 2. Express middleware — grade yourself on every boot

Instead of remembering to run a command, let your app grade itself in development:

```js
import helmet from "helmet";
import { headerGrader } from "header-grader/middleware";

app.use(helmet());

// Mount AFTER helmet/header middleware so it sees the final headers:
if (app.get("env") === "development") {
  app.use(headerGrader());
}
```

The first time your app serves an HTML response, the report prints to the console — then it stays quiet. It grades the headers your app *actually sends*, after all middleware has run, which catches misconfigurations that reading your helmet config never would.

Works with any Connect-compatible framework (Express, plain `node:http` handlers, etc.).

**Middleware options:**

| Option | Default | Description |
| --- | --- | --- |
| `watch` | `false` | Keep grading; reprint whenever the grade changes |
| `explain` | `false` | Include the attack scenario for each failing header |
| `onReport` | — | `(report) => void` — receive the report object instead of console output |
| `isLocalHttp` | `true` | Relax HSTS scoring (browsers ignore HSTS over plain HTTP) |

### 3. CI — enforce a minimum grade

Fail the build if headers regress:

```yaml
# .github/workflows/ci.yml (excerpt)
- run: npm start &
- run: npx wait-on http://localhost:3000
- run: npx header-grader http://localhost:3000 --min-grade B
```

`--json` gives you a machine-readable report if you want custom tooling:

```sh
header-grader localhost:3000 --json | jq .score
```

### 4. Programmatic API

```ts
import {
  scan,           // fetch a URL and grade it
  gradeHeaders,   // grade headers you already have (no network)
  generateExpress,
  generateNginx,
} from "header-grader";

const report = await scan("http://localhost:3000");
report.grade;   // "F"
report.score;   // 13
report.results; // per-header CheckResult[]: status, message, recommended value,
                // and — for anything not passing — an `exploit` field with the
                // concrete attack scenario (also present in --json output)

console.log(generateNginx(report));

// No network needed — useful in tests:
const r = gradeHeaders({ "x-content-type-options": "nosniff" }, { isLocalHttp: true });
```

Full types (`Report`, `CheckResult`, `Grade`, `Rule`, …) are exported.

## What it checks

Weighted checks (contribute to the score):

| Header | Weight | What passes |
| --- | ---: | --- |
| `Content-Security-Policy` | 25 | Present, without `unsafe-inline`/`unsafe-eval` in scripts or wildcard sources |
| `Strict-Transport-Security` | 20 | `max-age` ≥ 180 days; `includeSubDomains` recommended. Relaxed on plain-HTTP localhost |
| `X-Content-Type-Options` | 10 | Exactly `nosniff` |
| `X-Frame-Options` | 10 | `DENY`/`SAMEORIGIN` — or CSP `frame-ancestors`, which supersedes it |
| `Referrer-Policy` | 10 | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | 10 | Present (disable features you don't use) |
| `Cross-Origin-Opener-Policy` | 5 | Present (window isolation, Spectre-class protection) |
| `Cross-Origin-Resource-Policy` | 5 | Present (controls who may embed your resources) |

Hygiene penalties (subtract points):

| Header | Penalty | Why |
| --- | ---: | --- |
| `X-Powered-By` | −3 | Advertises your framework to attackers |
| `Server` with a version number | −3 | Advertises exact software versions |
| `X-XSS-Protection` (non-zero) | −2 | Deprecated; can *introduce* vulnerabilities. Use CSP instead |

**Grade scale:** A+ ≥ 95 · A ≥ 88 · B ≥ 75 · C ≥ 60 · D ≥ 45 · F below.

Notable grading behaviors:

- `unsafe-inline` is only flagged in `script-src` (or an inherited `default-src`) — inline *styles* are a much smaller risk and common in dev.
- CSP `frame-ancestors` satisfies the clickjacking check even without `X-Frame-Options`, matching modern browser behavior.
- Missing HSTS on `http://localhost` is a soft warning, not a failure — browsers ignore HSTS over HTTP, so punishing dev servers for it is noise.

## Design goals

- **Zero runtime dependencies.** The published package depends on nothing; `npx` startup stays fast and the supply-chain surface stays at zero.
- **One ruleset, three surfaces.** The CLI, the middleware, and the API all run the same rules, and the report and the generated snippets are derived from the same recommended values — they can never disagree.
- **Minimal-diff fixes.** Generated config only covers what's failing, so it composes with whatever you already have.

## Project structure

```
src/
├── types.ts          # Report, CheckResult, Grade, Rule
├── rules.ts          # one weighted rule per header + recommended values + exploit scenarios
├── grade.ts          # weighted score → letter grade
├── scan.ts           # fetch URL → headers → report
├── report.ts         # ANSI terminal formatting
├── generators/
│   ├── express.ts    # helmet config snippet
│   └── nginx.ts      # add_header block
├── cli.ts            # argument parsing + exit codes
├── middleware.ts     # Express/Connect middleware
└── index.ts          # public API
```

## Development

```sh
npm install
npm test            # vitest — rules, generators, middleware (real HTTP server)
npm run typecheck   # tsc --noEmit
npm run build       # tsup → dist/ (ESM + CJS + .d.ts)
```

Try it against a deliberately bad server:

```sh
node -e 'require("http").createServer((q,s)=>{s.setHeader("Content-Type","text/html");s.end("hi")}).listen(3456)' &
node dist/cli.js localhost:3456 --fix express
```

## Roadmap

- [ ] Caddy and Apache config generators
- [ ] `--watch` CLI mode — re-grade automatically as you edit config
- [ ] CSP builder: crawl the page's actual script/style origins and propose a tailored policy
- [ ] `Report-Only` CSP suggestion mode for safe rollout

## License

MIT
