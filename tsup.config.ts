import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/middleware.ts", "src/cli.ts"],
  format: ["esm", "cjs"],
  dts: { entry: ["src/index.ts", "src/middleware.ts"] },
  clean: true,
  target: "node18",
});
