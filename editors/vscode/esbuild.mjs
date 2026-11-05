import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "out/extension.js",
  external: ["vscode"],
  platform: "node",
  format: "cjs",
  target: "node18",
  minify: true,
  sourcemap: false,
  legalComments: "none",
  logLevel: "info",
});
