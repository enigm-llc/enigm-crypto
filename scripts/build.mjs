import { rm, mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
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
// Normalize only proven no-ops in generated bundles. Keep the maintained source
// and third-party dependency bytes unchanged. Source tests retain the engine hook.
const normalizeBundle = (code) => {
  const hmacClone = "    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;\n    to = to;\n";
  code = code.replaceAll(hmacClone, hmacClone.replace("    to = to;\n", ""));
  const declaration = "var override;\n";
  const engine = "var engine = () => override ?? (selected ??= select());";
  // An override setter/reference makes this optimization inapplicable. In public
  // bundles esbuild drops the unexported test hooks, leaving exactly these two uses.
  if (code.includes(declaration) && code.includes(engine) &&
      [...code.matchAll(/\boverride\b/g)].length === 2) {
    code = code.replace(declaration, "")
      .replace(engine, "var engine = () => selected ??= select();");
  }
  return code;
};

await Promise.all([
  ["esm", "dist"],
  ["cjs", "dist-cjs"],
].map(async ([format, outdir]) => {
  const result = await build({
    entryPoints,
    outdir,
    format,
    bundle: true,
    write: false,
    treeShaking: true,
    platform: "neutral",
    target: "es2022",
    legalComments: "inline",
  });
  await Promise.all(result.outputFiles.map(async (file) => {
    await mkdir(dirname(file.path), { recursive: true });
    await writeFile(file.path, normalizeBundle(file.text));
  }));
}));
await mkdir("dist-cjs", { recursive: true });
await writeFile(
  "dist-cjs/package.json",
  JSON.stringify({ type: "commonjs" }) + "\n"
);
