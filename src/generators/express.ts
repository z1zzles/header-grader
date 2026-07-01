import { RECOMMENDED } from "../rules.js";
import type { Report } from "../types.js";

/**
 * Generate an Express (helmet) snippet that fixes everything the report
 * flagged. Only includes config for headers that aren't already passing,
 * so the snippet is a minimal diff against the user's current setup.
 */
export function generateExpress(report: Report): string {
  const failing = new Set(
    report.results.filter((r) => r.status !== "pass").map((r) => r.header)
  );

  const lines: string[] = [
    "// npm install helmet",
    'import helmet from "helmet";',
    "",
    "app.use(",
    "  helmet({",
  ];

  if (failing.has("Content-Security-Policy")) {
    lines.push(
      "    contentSecurityPolicy: {",
      "      directives: {",
      '        defaultSrc: ["\'self\'"],',
      '        scriptSrc: ["\'self\'"], // add CDN origins here as needed',
      '        objectSrc: ["\'none\'"],',
      '        baseUri: ["\'self\'"],',
      '        frameAncestors: ["\'self\'"],',
      "      },",
      "    },"
    );
  }
  if (failing.has("Strict-Transport-Security")) {
    lines.push(
      "    strictTransportSecurity: {",
      "      maxAge: 31536000, // 1 year — browsers only honor this over HTTPS",
      "      includeSubDomains: true,",
      "    },"
    );
  }
  if (failing.has("X-Frame-Options")) {
    lines.push('    xFrameOptions: { action: "sameorigin" },');
  }
  if (failing.has("Referrer-Policy")) {
    lines.push('    referrerPolicy: { policy: "strict-origin-when-cross-origin" },');
  }
  if (failing.has("Cross-Origin-Opener-Policy")) {
    lines.push('    crossOriginOpenerPolicy: { policy: "same-origin" },');
  }
  if (failing.has("Cross-Origin-Resource-Policy")) {
    lines.push('    crossOriginResourcePolicy: { policy: "same-origin" },');
  }

  lines.push("  })", ");");

  // Helmet doesn't manage Permissions-Policy; set it directly.
  if (failing.has("Permissions-Policy")) {
    lines.push(
      "",
      "// Helmet doesn't set Permissions-Policy — add it yourself:",
      "app.use((req, res, next) => {",
      `  res.setHeader("Permissions-Policy", "${RECOMMENDED["Permissions-Policy"]}");`,
      "  next();",
      "});"
    );
  }

  if (failing.has("X-Powered-By")) {
    lines.push("", '// Stop advertising Express:', 'app.disable("x-powered-by");');
  }

  return lines.join("\n");
}
