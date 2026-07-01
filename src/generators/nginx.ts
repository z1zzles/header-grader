import { RECOMMENDED } from "../rules.js";
import type { Report } from "../types.js";

/**
 * Generate an nginx `server {}` block fragment that fixes everything the
 * report flagged. `always` makes the headers apply to error responses too.
 */
export function generateNginx(report: Report): string {
  const failing = new Set(
    report.results.filter((r) => r.status !== "pass").map((r) => r.header)
  );

  const lines: string[] = ["# Add inside your server {} block"];

  const addable: Array<keyof typeof RECOMMENDED> = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
  ];

  for (const header of addable) {
    if (failing.has(header)) {
      lines.push(`add_header ${header} "${RECOMMENDED[header]}" always;`);
    }
  }

  if (failing.has("Server")) {
    lines.push("", "# Hide the nginx version number:", "server_tokens off;");
  }
  if (failing.has("X-Powered-By")) {
    lines.push(
      "",
      "# Strip the backend's X-Powered-By before it reaches clients:",
      "proxy_hide_header X-Powered-By;"
    );
  }
  if (failing.has("X-XSS-Protection")) {
    lines.push(
      "",
      "# X-XSS-Protection is deprecated; strip it from the backend:",
      "proxy_hide_header X-XSS-Protection;"
    );
  }

  return lines.join("\n");
}
