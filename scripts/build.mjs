import { rm, mkdir, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";
for (const directory of ["dist", "dist-cjs"])
  await rm(directory, { recursive: true, force: true });
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
for (const [format, outdir] of [
  ["esm", "dist"],
  ["cjs", "dist-cjs"],
]) {
  await build({
    entryPoints,
    outdir,
    format,
    bundle: true,
    treeShaking: true,
    platform: "neutral",
    target: "es2022",
    legalComments: "inline",
  });
}
await mkdir("dist-cjs", { recursive: true });
await writeFile(
  "dist-cjs/package.json",
  JSON.stringify({ type: "commonjs" }) + "\n"
);
