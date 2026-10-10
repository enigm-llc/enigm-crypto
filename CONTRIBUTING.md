# Contributing to Enigm Crypto

Enigm Crypto is security-sensitive code. Small, reviewable changes with explicit tests are easier
to validate than broad refactors.

## Development workflow

1. Install Node.js 20.19 or newer and run `npm ci --ignore-scripts`.
2. Add tests for every changed success and failure condition.
3. Run `npm audit --audit-level=high` and `npm audit signatures`.
4. Run `npm run check`, `npm test`, `npm run examples`, `npm run test:runtime`,
   `npm run test:package`, `npm run release:check`, `npm run pack:verify` and
   `npm pack --dry-run`.
5. Explain any wire-format, transcript, suite or state-transition change in the pull request.
6. Update `docs/PROTOCOL.md` when a protocol-visible value changes.

Do not include production keys, user data, provider credentials or private interoperability traces
in an issue, commit or test fixture. Report suspected vulnerabilities through the process in
`SECURITY.md` rather than opening a public issue.

Public documentation and examples must use supported package imports, contain no internal workflow
instructions or workstation paths, and describe privacy/recovery limits accurately. Change release
metadata together with the lockfile and changelog; follow [Release](docs/RELEASE.md).
