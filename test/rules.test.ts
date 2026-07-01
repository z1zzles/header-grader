import { describe, expect, it } from "vitest";
import { gradeHeaders } from "../src/scan.js";
import type { Headers } from "../src/types.js";

const STRONG_HEADERS: Headers = {
  "content-security-policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};

function resultFor(headers: Headers, header: string, isLocalHttp = false) {
  const report = gradeHeaders(headers, { isLocalHttp });
  const result = report.results.find((r) => r.header === header);
  if (!result) throw new Error(`no result for ${header}`);
  return result;
}

describe("grading extremes", () => {
  it("gives A+ to a fully hardened response", () => {
    const report = gradeHeaders(STRONG_HEADERS);
    expect(report.grade).toBe("A+");
    expect(report.score).toBe(100);
  });

  it("gives F to a bare response", () => {
    const report = gradeHeaders({});
    expect(report.grade).toBe("F");
  });
});

describe("Content-Security-Policy", () => {
  it("fails when missing", () => {
    expect(resultFor({}, "Content-Security-Policy").status).toBe("fail");
  });

  it("warns on unsafe-inline in script-src", () => {
    const r = resultFor(
      { "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" },
      "Content-Security-Policy"
    );
    expect(r.status).toBe("warn");
    expect(r.message).toContain("unsafe-inline");
  });

  it("warns on unsafe-eval", () => {
    const r = resultFor(
      { "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'" },
      "Content-Security-Policy"
    );
    expect(r.status).toBe("warn");
    expect(r.message).toContain("unsafe-eval");
  });

  it("gives partial credit for a report-only policy", () => {
    const r = resultFor(
      { "content-security-policy-report-only": "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'" },
      "Content-Security-Policy"
    );
    expect(r.status).toBe("warn");
    expect(r.message).toContain("Report-Only");
    expect(r.earned).toBeGreaterThan(0);
    expect(r.earned).toBeLessThan(r.weight);
  });

  it("does not flag unsafe-inline that only appears in style-src", () => {
    const r = resultFor(
      { "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" },
      "Content-Security-Policy"
    );
    expect(r.status).toBe("pass");
  });
});

describe("Strict-Transport-Security", () => {
  it("fails when missing on a non-local target", () => {
    expect(resultFor({}, "Strict-Transport-Security", false).status).toBe("fail");
  });

  it("softens to a warn on local HTTP (dev mode)", () => {
    const r = resultFor({}, "Strict-Transport-Security", true);
    expect(r.status).toBe("warn");
    expect(r.earned).toBeGreaterThan(0);
  });

  it("warns on a short max-age", () => {
    const r = resultFor({ "strict-transport-security": "max-age=300" }, "Strict-Transport-Security");
    expect(r.status).toBe("warn");
  });
});

describe("X-Frame-Options", () => {
  it("passes when CSP frame-ancestors covers it", () => {
    const r = resultFor(
      { "content-security-policy": "default-src 'self'; frame-ancestors 'none'" },
      "X-Frame-Options"
    );
    expect(r.status).toBe("pass");
  });

  it("fails when neither XFO nor frame-ancestors is set", () => {
    expect(resultFor({}, "X-Frame-Options").status).toBe("fail");
  });

  it("accepts DENY case-insensitively", () => {
    expect(resultFor({ "x-frame-options": "deny" }, "X-Frame-Options").status).toBe("pass");
  });
});

describe("hygiene penalties", () => {
  it("penalizes X-Powered-By", () => {
    const r = resultFor({ "x-powered-by": "Express" }, "X-Powered-By");
    expect(r.status).toBe("warn");
    expect(r.earned).toBeLessThan(0);
  });

  it("penalizes Server headers that leak versions but not bare product names", () => {
    expect(resultFor({ server: "nginx/1.25.3" }, "Server").earned).toBeLessThan(0);
    expect(resultFor({ server: "nginx" }, "Server").earned).toBe(0);
  });

  it("flags deprecated X-XSS-Protection unless it is 0", () => {
    expect(resultFor({ "x-xss-protection": "1; mode=block" }, "X-XSS-Protection").status).toBe("warn");
    expect(resultFor({ "x-xss-protection": "0" }, "X-XSS-Protection").status).toBe("pass");
  });
});

describe("exploit explanations", () => {
  it("attaches an attack scenario to every non-passing check", () => {
    const report = gradeHeaders({ "x-powered-by": "Express", server: "nginx/1.25.3" });
    const failing = report.results.filter((r) => r.status !== "pass");
    expect(failing.length).toBeGreaterThan(0);
    for (const r of failing) {
      expect(r.exploit, `${r.header} should explain its exploit`).toBeTruthy();
    }
  });

  it("omits the scenario on passing checks", () => {
    const report = gradeHeaders(STRONG_HEADERS);
    for (const r of report.results.filter((x) => x.status === "pass")) {
      expect(r.exploit).toBeUndefined();
    }
  });
});

describe("header normalization", () => {
  it("accepts mixed-case header names", () => {
    const report = gradeHeaders({ "X-Content-Type-Options": "nosniff" } as Headers);
    const r = report.results.find((x) => x.header === "X-Content-Type-Options");
    expect(r?.status).toBe("pass");
  });
});
