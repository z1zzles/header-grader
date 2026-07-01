import { describe, expect, it } from "vitest";
import { gradeHeaders } from "../src/scan.js";
import { generateExpress } from "../src/generators/express.js";
import { generateNginx } from "../src/generators/nginx.js";

describe("generateExpress", () => {
  it("includes fixes for everything failing on a bare server", () => {
    const report = gradeHeaders({ "x-powered-by": "Express" }, { isLocalHttp: true });
    const snippet = generateExpress(report);
    expect(snippet).toContain("helmet");
    expect(snippet).toContain("contentSecurityPolicy");
    expect(snippet).toContain("Permissions-Policy");
    expect(snippet).toContain('app.disable("x-powered-by")');
  });

  it("omits config for headers that already pass", () => {
    const report = gradeHeaders({
      "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
      "x-content-type-options": "nosniff",
    });
    const snippet = generateExpress(report);
    expect(snippet).not.toContain("contentSecurityPolicy");
    // XFO passes via frame-ancestors, so no xFrameOptions config either.
    expect(snippet).not.toContain("xFrameOptions");
  });
});

describe("generateNginx", () => {
  it("emits add_header lines for missing headers", () => {
    const report = gradeHeaders({});
    const snippet = generateNginx(report);
    expect(snippet).toContain('add_header Content-Security-Policy');
    expect(snippet).toContain("always;");
  });

  it("suggests server_tokens off when the Server header leaks a version", () => {
    const report = gradeHeaders({ server: "nginx/1.25.3" });
    expect(generateNginx(report)).toContain("server_tokens off;");
  });
});
