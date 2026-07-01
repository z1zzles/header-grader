#!/usr/bin/env node
import { scan } from "./scan.js";
import { formatReport } from "./report.js";
import { generateExpress } from "./generators/express.js";
import { generateNginx } from "./generators/nginx.js";
import { isGrade, meetsGrade } from "./grade.js";

const HELP = `header-grader — grade your dev server's security headers

Usage:
  header-grader <url> [options]

Options:
  --explain               Show how each missing header could be exploited
  --fix <express|nginx>   Print a config snippet that fixes the failing headers
  --json                  Output the full report as JSON
  --min-grade <grade>     Exit 1 if the grade is below this (A+, A, B, C, D) — for CI
  -h, --help              Show this help

Examples:
  header-grader localhost:3000
  header-grader localhost:3000 --explain
  header-grader http://localhost:8080 --fix nginx
  header-grader localhost:3000 --min-grade B --json
`;

interface Args {
  url: string;
  fix?: "express" | "nginx";
  json: boolean;
  explain: boolean;
  minGrade?: string;
}

function parseArgs(argv: string[]): Args | null {
  const args: Args = { url: "", json: false, explain: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case "-h":
      case "--help":
        return null;
      case "--json":
        args.json = true;
        break;
      case "--explain":
        args.explain = true;
        break;
      case "--fix": {
        const target = argv[++i];
        if (target !== "express" && target !== "nginx") {
          throw new Error(`--fix expects "express" or "nginx", got "${target ?? ""}"`);
        }
        args.fix = target;
        break;
      }
      case "--min-grade": {
        const grade = argv[++i]?.toUpperCase();
        if (!grade || !isGrade(grade)) {
          throw new Error(`--min-grade expects one of A+, A, B, C, D, F — got "${grade ?? ""}"`);
        }
        args.minGrade = grade;
        break;
      }
      default:
        if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
        if (args.url) throw new Error("Only one URL at a time.");
        args.url = arg;
    }
  }
  if (!args.url) throw new Error("Missing URL. Try: header-grader localhost:3000");
  return args;
}

async function main(): Promise<void> {
  let args: Args | null;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`Error: ${(err as Error).message}\n`);
    console.error(HELP);
    process.exit(2);
  }
  if (args === null) {
    console.log(HELP);
    return;
  }

  let report;
  try {
    report = await scan(args.url);
  } catch (err) {
    const cause = (err as { cause?: { code?: string } }).cause;
    if (cause?.code === "ECONNREFUSED") {
      console.error(`Could not connect to ${args.url} — is your dev server running?`);
    } else {
      console.error(`Failed to scan ${args.url}: ${(err as Error).message}`);
    }
    process.exit(2);
  }

  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatReport(report, { explain: args.explain }));
  }

  if (args.fix) {
    const snippet = args.fix === "express" ? generateExpress(report) : generateNginx(report);
    if (!args.json) console.log("─".repeat(60) + "\n");
    console.log(snippet);
    console.log("");
  }

  if (args.minGrade && isGrade(args.minGrade) && !meetsGrade(report.grade, args.minGrade)) {
    console.error(`Grade ${report.grade} is below the required minimum of ${args.minGrade}.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
