import { rm, mkdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";
await Promise.all(["dist", "dist-cjs"].map(directory =>
  rm(directory, { recursive: true, force: true })
));
execFileSync(
  process.execPath,
  [
    "node_modules/typescript/bin/tsc",
    "-p",
    "tsconfig.json",
    "--emitDeclarationOnly",
  ],
  { stdio: "inherit" }
);
const entryPoints = {
  index: "src/index.ts",
  "core/index": "src/core/index.ts",
  "primitives/index": "src/primitives/index.ts",
  "protocols/index": "src/protocols/index.ts",
  "codecs/index": "src/codecs/index.ts",
  "sdk/index": "src/sdk/index.ts",
};
await Promise.all([
  ["esm", "dist"],
  ["cjs", "dist-cjs"],
].map(([format, outdir]) => build({
    entryPoints,
    outdir,
    format,
    bundle: true,
    treeShaking: true,
    platform: "neutral",
    target: "es2022",
    legalComments: "inline",
  })));
await mkdir("dist-cjs", { recursive: true });
await writeFile(
  "dist-cjs/package.json",
  JSON.stringify({ type: "commonjs" }) + "\n"
);
