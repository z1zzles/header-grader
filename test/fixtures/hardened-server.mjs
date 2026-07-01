// Fixture: a fully hardened server. The CI dogfood step expects this to
// earn A+ and pass `--min-grade A+`.
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 3457);

const HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Type": "text/html; charset=utf-8",
};

createServer((req, res) => {
  for (const [name, value] of Object.entries(HEADERS)) res.setHeader(name, value);
  res.end("<h1>hardened fixture</h1>");
}).listen(PORT, "127.0.0.1", () => console.log(`hardened fixture listening on ${PORT}`));
