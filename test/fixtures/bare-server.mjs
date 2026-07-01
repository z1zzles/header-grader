// Fixture: a typical unhardened dev server. The CI dogfood step expects
// this to grade F and make `--min-grade B` exit 1.
import { createServer } from "node:http";

const PORT = Number(process.env.PORT ?? 3456);

createServer((req, res) => {
  res.setHeader("X-Powered-By", "Express");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end("<h1>bare fixture</h1>");
}).listen(PORT, "127.0.0.1", () => console.log(`bare fixture listening on ${PORT}`));
