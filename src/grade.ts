import type { CheckResult, Grade } from "./types.js";

export function scoreOf(results: CheckResult[]): number {
  const maxPoints = results.reduce((sum, r) => sum + r.weight, 0);
  const earned = results.reduce((sum, r) => sum + r.earned, 0);
  if (maxPoints === 0) return 0;
  const pct = (earned / maxPoints) * 100;
  return Math.max(0, Math.min(100, Math.round(pct)));
}

export function gradeOf(score: number): Grade {
  if (score >= 95) return "A+";
  if (score >= 88) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

const GRADE_ORDER: Grade[] = ["F", "D", "C", "B", "A", "A+"];

/** True if `actual` is at least as good as `minimum`. */
export function meetsGrade(actual: Grade, minimum: Grade): boolean {
  return GRADE_ORDER.indexOf(actual) >= GRADE_ORDER.indexOf(minimum);
}

export function isGrade(value: string): value is Grade {
  return (GRADE_ORDER as string[]).includes(value);
}
