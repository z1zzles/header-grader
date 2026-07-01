import type { IncomingMessage, ServerResponse } from "node:http";
import { gradeHeaders } from "./scan.js";
import { formatReport } from "./report.js";
import type { Report } from "./types.js";

export interface MiddlewareOptions {
  /**
   * Grade every response, deduped by grade — reprints only when the grade
   * changes. Default: grade only the first HTML/document response.
   */
  watch?: boolean;
  /** Called with the report instead of printing to the console. */
  onReport?: (report: Report) => void;
  /** Treat the server as local HTTP (relaxes HSTS). Default: true — it's a dev tool. */
  isLocalHttp?: boolean;
}

/**
 * Express/Connect-compatible middleware that grades the security headers
 * your own app actually sends. Mount it AFTER helmet/header middleware so
 * it sees the final headers:
 *
 *   app.use(helmet());
 *   if (app.get("env") === "development") app.use(headerGrader());
 */
export function headerGrader(options: MiddlewareOptions = {}) {
  const { watch = false, onReport, isLocalHttp = true } = options;
  let done = false;
  let lastGrade: string | undefined;

  return function headerGraderMiddleware(
    req: IncomingMessage,
    res: ServerResponse,
    next: (err?: unknown) => void
  ): void {
    if (done && !watch) return next();

    res.once("finish", () => {
      if (done && !watch) return;
      // Only grade document responses — asset requests aren't interesting.
      const contentType = String(res.getHeader("content-type") ?? "");
      const isDocument = contentType.includes("text/html") || contentType === "";
      if (!isDocument) return;

      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(res.getHeaders())) {
        if (value !== undefined) {
          headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
        }
      }

      const report = gradeHeaders(headers, {
        url: `${req.method ?? "GET"} ${req.url ?? "/"}`,
        isLocalHttp,
      });

      done = true;
      if (watch && report.grade === lastGrade) return;
      lastGrade = report.grade;

      if (onReport) {
        onReport(report);
      } else {
        console.log(formatReport(report));
      }
    });

    next();
  };
}

export default headerGrader;
