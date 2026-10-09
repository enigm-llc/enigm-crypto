# npm release procedure

## Release policy

`1.0.0` is the planned first final release, distributed under Apache-2.0 with bundled Noble MIT
notices. It remains unreleased while development and validation are incomplete. The public npm
registry is `https://registry.npmjs.org`; final releases use the `latest` dist-tag. The workflows
reject prerelease versions and versions below 1.0.0.

Publish only after the agreed feature scope is complete, physical iOS/Android acceptance and
independent cryptographic review are complete, and the documented security/privacy requirements
and external release controls have been verified. Participant anonymity is currently unmet; resolve
that requirement before approving the final release. A version number or passing CI does not
establish production readiness or anonymity.

The repository prepares two processes:

- `release.yml` validates a version-matching tag on main, verifies/builds the package, attests the
  tarball and SBOM, and creates a GitHub release with those artifacts.
- `publish.yml` is manually dispatched for a reviewed version-matching tag on main. It rebuilds
  with the locked dependencies, runs the release checks, verifies the downloaded checksum,
  attests the exact tarball/SBOM, then submits that tarball through npm trusted publishing to
  the staging area. It does not directly make the candidate version public.

No workflow is run merely by editing this document. Do not dispatch staging, create a tag,
merge a release commit or approve a package without release authorization.

## One-time external setup

These controls cannot be established by package source alone:

1. Confirm publishing rights in the npm `@enigm` scope and enable maintainer 2FA. Public registry
   lookup of an absent package does not prove namespace ownership.
2. Configure GitHub tag/main rules and protected `release`/`npm-release` environments with required
   reviewers and suitable tag/branch restrictions. Creating a named environment is not itself
   proof that reviewers or restrictions have been configured.
3. Configure the package's npm trusted publisher for organization `enigm-llc`, repository
   `enigm-crypto`, workflow filename `publish.yml`, environment `npm-release`, stage-only permissions.
   Do not add a long-lived write token to the repository.
4. Set `NPM_RELEASE_READY=true` in the `npm-release` environment only after final release acceptance, these controls and
   publisher configuration have been verified. Without it, the staging job fails closed.
5. If the package has no settings page yet, an authorized maintainer must bootstrap the npm
   package/scope using npm's supported first-publication/staging process, then configure trusted
   publishing. Staging a new package creates a public `0.0.0-stage` placeholder; treat even this
   bootstrap as an authorized registry change. Do not assume an unpublished package can already
   authenticate a configured trusted publisher.

Trusted publishing requires Node >=22.14 and npm >=11.5.1. The staged flow additionally requires
npm >=11.15.0. The staging workflow selects Node 24.20.0 and verifies availability of the stage
command. Library consumer support remains Node >=20.19; release tooling has a different floor.
Configure the trusted publisher shortly before the first release: npm currently expires unused
new publisher configurations after two days.

See the official [trusted-publisher documentation](https://docs.npmjs.com/trusted-publishers/)
and [staged publishing documentation](https://docs.npmjs.com/staged-publishing/) for the current
registry requirements. OIDC provenance is automatically generated for public GitHub repositories
and public npm packages; GitHub build/SBOM attestations are additional, separate evidence.

## Candidate verification

From a clean source checkout, with the committed lockfile:

```sh
npm ci --ignore-scripts
npm audit --audit-level=high
npm audit signatures
npm run check
npm test
npm run examples
npm run benchmark
npm run test:runtime
npm run test:package
npm run release:check
npm run pack:verify
npm run --silent sbom > enigm-crypto.cdx.json
npm pack --dry-run
node scripts/verify-release.mjs --tag v1.0.0
```

`test:package` checks the tarball's ESM/CJS/React Native imports, modular exports, TypeScript
consumer declarations, real offline npm installation and shipped examples. `release:check`
checks manifest/lock identity, public file allowlist, documentation links/content and bundled
licenses. `pack:verify` performs two clean output rebuilds under the same locked toolchain and
compares tarball SHA-256 values; it does not prove equivalence across arbitrary toolchains.

Only public docs, examples, source, compiled code/declarations and licenses may ship. Internal
plans, credentials, application code, tests, development scripts and machine-specific paths
must not enter the archive. Confirm the SBOM includes pinned components actually bundled in
compiled entries. Verify the final payload instead of trusting a filename or npm dry-run alone.

The additional Hermes harness requires a source checkout and host React Native tooling. Record
physical iOS/Android acceptance separately; library VM tests do not establish native storage,
network, notifications or multimedia behavior.

## Authorized release

After reviews and checks pass, merge the reviewed commit, create its exact `vVERSION` tag on main,
and review the generated GitHub release/checksums/attestations. Dispatch `publish.yml` **on the same tag ref**, with
that tag input only after external setup is complete. The workflow ref must equal the requested tag so OIDC provenance records the actual release
commit, not the branch from which dispatch was requested. Never rebuild a different tarball in the stage
job or run lifecycle scripts from the downloaded candidate.

An authorized npm maintainer reviews the staged package, downloads and compares its tarball,
checks provenance, version, license and tag, then approves it with 2FA:

```sh
npm stage list @enigm/crypto
npm stage view STAGE_ID
npm stage download STAGE_ID
# Publication occurs only when the authorized maintainer executes this:
npm stage approve STAGE_ID
```

Once approved, verify installation from the registry and the `latest` dist-tag in a clean consumer.
If staging is wrong, reject it rather than approving and attempting to replace an immutable
published version. A wrong public release requires a new version and an appropriate advisory.
