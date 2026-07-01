import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { headerGrader } from "../src/middleware.js";
import type { Report } from "../src/types.js";

let close: (() => Promise<void>) | undefined;
afterEach(async () => {
  await close?.();
  close = undefined;
});

function startServer(handler: Parameters<typeof createServer>[1]) {
  const server = createServer(handler);
  return new Promise<string>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      close = () => new Promise((r) => server.close(() => r()));
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

describe("headerGrader middleware", () => {
  it("grades the headers the response actually sends", async () => {
    const reports: Report[] = [];
    const mw = headerGrader({ onReport: (r) => reports.push(r) });

    const url = await startServer((req, res) => {
      mw(req, res, () => {
        res.setHeader("content-type", "text/html");
        res.setHeader("x-content-type-options", "nosniff");
        res.end("<h1>hi</h1>");
      });
    });

    await fetch(url);
    // 'finish' fires asynchronously after the response completes.
    await new Promise((r) => setTimeout(r, 50));

    expect(reports).toHaveLength(1);
    const nosniff = reports[0]!.results.find((r) => r.header === "X-Content-Type-Options");
    expect(nosniff?.status).toBe("pass");
    const csp = reports[0]!.results.find((r) => r.header === "Content-Security-Policy");
    expect(csp?.status).toBe("fail");
  });

  it("only reports once by default", async () => {
    const reports: Report[] = [];
    const mw = headerGrader({ onReport: (r) => reports.push(r) });

    const url = await startServer((req, res) => {
      mw(req, res, () => {
        res.setHeader("content-type", "text/html");
        res.end("ok");
      });
    });

    await fetch(url);
    await fetch(url);
    await new Promise((r) => setTimeout(r, 50));
    expect(reports).toHaveLength(1);
  });

  it("skips non-document responses", async () => {
    const reports: Report[] = [];
    const mw = headerGrader({ onReport: (r) => reports.push(r) });

    const url = await startServer((req, res) => {
      mw(req, res, () => {
        res.setHeader("content-type", "application/json");
        res.end("{}");
      });
    });

    await fetch(url);
    await new Promise((r) => setTimeout(r, 50));
    expect(reports).toHaveLength(0);
  });
});
