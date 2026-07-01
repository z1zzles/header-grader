import { runRules } from "./rules.js";
import { gradeOf, scoreOf } from "./grade.js";
import type { Headers, Report, ScanContext } from "./types.js";

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "0.0.0.0"]);

export function isLocalHttpUrl(url: URL): boolean {
  return url.protocol === "http:" && LOCAL_HOSTS.has(url.hostname);
}

/** Grade a set of already-collected headers (used by the middleware and tests). */
export function gradeHeaders(headers: Headers, opts: { url?: string; isLocalHttp?: boolean } = {}): Report {
  const ctx: ScanContext = {
    headers: normalizeHeaders(headers),
    isLocalHttp: opts.isLocalHttp ?? false,
  };
  const results = runRules(ctx);
  const score = scoreOf(results);
  return {
    url: opts.url ?? "(headers)",
    grade: gradeOf(score),
    score,
    results,
    fetchedAt: new Date().toISOString(),
  };
}

/** Fetch a URL and grade its response headers. */
export async function scan(rawUrl: string, opts: { timeoutMs?: number } = {}): Promise<Report> {
  const url = new URL(rawUrl.includes("://") ? rawUrl : `http://${rawUrl}`);
  const res = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000),
    headers: { "user-agent": "header-grader (local dev security check)" },
  });
  // Drain the body so the connection is released.
  await res.arrayBuffer().catch(() => undefined);

  const headers: Headers = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  return gradeHeaders(headers, { url: url.href, isLocalHttp: isLocalHttpUrl(url) });
}

function normalizeHeaders(headers: Headers): Headers {
  const out: Headers = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key.toLowerCase()] = value;
  }
  return out;
}
