/** Lowercased header name → value. Multi-value headers are comma-joined. */
export type Headers = Record<string, string>;

export type Status = "pass" | "warn" | "fail";

export interface CheckResult {
  /** Canonical header name, e.g. "Content-Security-Policy" */
  header: string;
  status: Status;
  /** Human explanation of what was found (or not). */
  message: string;
  /** Points earned toward the score. */
  earned: number;
  /** Max points this rule is worth. 0 for penalty-only rules. */
  weight: number;
  /** The value we recommend setting, when status != pass. */
  recommended?: string;
  /** Concrete attack scenario this header prevents, when status != pass. */
  exploit?: string;
}

export interface ScanContext {
  headers: Headers;
  /** True when the target is plain HTTP on localhost — dev mode. */
  isLocalHttp: boolean;
}

export interface Rule {
  header: string;
  weight: number;
  check(ctx: ScanContext): CheckResult;
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface Report {
  url: string;
  grade: Grade;
  /** 0–100 */
  score: number;
  results: CheckResult[];
  fetchedAt: string;
}
