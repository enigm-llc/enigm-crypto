import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isAbsolute, join, dirname } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const npmCli = process.env.npm_execpath;
if (!npmCli || !isAbsolute(npmCli)) throw new Error('Run public package verification through npm.');
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const description = JSON.parse(execFileSync(process.execPath,
  [npmCli, 'pack', '--dry-run', '--ignore-scripts', '--json'], { cwd: root, encoding: 'utf8' }));
const files = description[0].files.map(file => file.path);
const roots = new Set(manifest.files);
for (const file of files) {
  assert(file === 'package.json' || [...roots].some(allowed => file === allowed || file.startsWith(`${allowed}/`)), `Unexpected public file: ${file}`);
  assert(!/(^|\/)(node_modules|\.git|\.env[^/]*|test|tests|scripts|superpowers|\.superpowers|\.codex)(\/|$)/u.test(file), `Internal payload: ${file}`);
}
for (const required of ['README.md', 'LICENSE', 'NOTICE', 'SECURITY.md', 'CHANGELOG.md', 'THIRD-PARTY-LICENSES.txt', 'docs/PRIVACY.md', 'docs/SECURITY-ASSESSMENT.md']) {
  assert(files.includes(required), `Missing public document: ${required}`);
}
const internalLanguage = /\b(?:Codex|ChatGPT|OpenAI|superpowers|agentic|SKILL\.md)\b|\/Users\/|\/Desktop\/projects\//iu;
const documents = files.filter(file => file.endsWith('.md'));
for (const file of documents) {
  const text = await readFile(join(root, file), 'utf8');
  assert(!internalLanguage.test(text), `Internal content in public documentation: ${file}`);
  for (const match of text.matchAll(/\[[^\]]+\]\(([^\s)]+)(?:\s+"[^"]*")?\)/gu)) {
    const link = match[1].split('#')[0];
    if (!link || /^[a-z]+:/iu.test(link)) continue;
    const target = join(dirname(file), link).replaceAll('\\', '/');
    assert(files.includes(target) || files.some(item => item.startsWith(`${target}/`)), `Broken public link in ${file}: ${link}`);
  }
}
for (const file of await readdir(join(root, 'examples'))) {
  if (!file.endsWith('.ts')) continue;
  const text = await readFile(join(root, 'examples', file), 'utf8');
  assert(!/from\s+['"]\.\.\/src\//u.test(text), `Private source import in example: ${file}`);
}
const notices = await readFile(join(root, 'THIRD-PARTY-LICENSES.txt'), 'utf8');
for (const [dependency, version] of Object.entries(manifest.dependencies)) {
  const license = await readFile(join(root, 'node_modules', dependency, 'LICENSE'), 'utf8');
  assert(notices.includes(`${dependency} ${version}`) && notices.includes(license.trim()), `Missing bundled license: ${dependency}`);
}
console.log(`Public package verified: ${files.length} allowlisted files, local links, consumer examples and bundled licenses.`);
