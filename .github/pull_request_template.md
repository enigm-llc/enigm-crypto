## Summary

Describe the change and its security impact.

## Verification

- [ ] `npm ci --ignore-scripts`
- [ ] `npm audit --audit-level=high`
- [ ] `npm audit signatures`
- [ ] `npm run check`
- [ ] `npm test`
- [ ] `npm run build`
- [ ] `npm run pack:verify`
- [ ] `npm pack --dry-run`

## Protocol impact

- [ ] No wire format, transcript, key derivation, cipher suite or state transition changes.
- [ ] Protocol-visible changes are documented and covered by interoperability and negative tests.
- [ ] No production keys, credentials, user data or private traces are included.
