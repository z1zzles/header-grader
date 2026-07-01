import type { Grade, Report, Status } from "./types.js";

// Minimal ANSI helpers — keeps us at zero runtime dependencies.
const useColor = process.stdout.isTTY && process.env["NO_COLOR"] === undefined;
const wrap = (code: number) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = wrap(31);
const green = wrap(32);
const yellow = wrap(33);
const dim = wrap(2);
const bold = wrap(1);

const STATUS_ICON: Record<Status, string> = {
  pass: green("✓"),
  warn: yellow("!"),
  fail: red("✗"),
};

function gradeColor(grade: Grade): (s: string) => string {
  if (grade === "A+" || grade === "A") return green;
  if (grade === "B" || grade === "C") return yellow;
  return red;
}

export function formatReport(report: Report): string {
  const lines: string[] = [];
  const color = gradeColor(report.grade);

  lines.push("");
  lines.push(`  ${bold(color(`Grade: ${report.grade}`))}  ${dim(`(${report.score}/100)`)}  ${dim(report.url)}`);
  lines.push("");

  // Scored rules first (heaviest first), then penalty/hygiene rules.
  const scored = report.results.filter((r) => r.weight > 0).sort((a, b) => b.weight - a.weight);
  const hygiene = report.results.filter((r) => r.weight === 0);

  for (const r of scored) {
    lines.push(`  ${STATUS_ICON[r.status]} ${bold(r.header)}`);
    lines.push(`    ${dim(r.message)}`);
  }

  const hygieneIssues = hygiene.filter((r) => r.status !== "pass");
  if (hygieneIssues.length > 0) {
    lines.push("");
    lines.push(`  ${dim("Hygiene:")}`);
    for (const r of hygieneIssues) {
      lines.push(`  ${STATUS_ICON[r.status]} ${bold(r.header)}`);
      lines.push(`    ${dim(r.message)}`);
    }
  }

  const fixable = report.results.some((r) => r.status !== "pass");
  if (fixable) {
    lines.push("");
    lines.push(`  ${dim("Generate the fix:")} header-grader ${report.url} --fix express ${dim("(or --fix nginx)")}`);
  }
  lines.push("");

  return lines.join("\n");
}
