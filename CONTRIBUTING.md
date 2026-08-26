# Contributing to Enigm Crypto

Enigm Crypto is security-sensitive code. Small, reviewable changes with explicit tests are easier
to validate than broad refactors.

## Development workflow

1. Install Node.js 20.19 or newer and run `npm ci`.
2. Add tests for every changed success and failure condition.
3. Run `npm run check`, `npm test`, `npm run build` and `npm pack --dry-run`.
4. Explain any wire-format, transcript, suite or state-transition change in the pull request.
5. Update `docs/PROTOCOL.md` and migration guidance when a protocol-visible value changes.

Do not include production keys, user data, provider credentials or private interoperability traces
in an issue, commit or test fixture. Report suspected vulnerabilities through the process in
`SECURITY.md` rather than opening a public issue.
