# Preparing an npm release

This branch prepares `0.2.0-alpha.0`; it does not publish to npm.
The package uses the existing Apache-2.0 license and includes bundled dependency notices.
The prerelease default tag is `next`. Confirm namespace ownership and release authorization
before publication. Registry publishing credentials/configuration remain a separate release task.

Run check, tests, examples, benchmark, runtime tests, packed-consumer tests, dependency audit,
reproducible packaging and SBOM generation using the locked toolchain. Inspect `npm pack --dry-run`:
only public documentation, examples, source, compiled code/declarations and licenses belong in
it. Internal plans, tests, scripts, credentials and app code must not ship. Test the resulting
tarball as a consumer before publication. Existing CI enforces the portable checks; Hermes/device
checks require the corresponding host tooling and devices.

Keep all existing root exports compatible. Protocol bytes, context strings, signatures and
hash inputs must remain stable unless a separately versioned protocol change is explicitly made.
This is pre-release cryptographic software with no independent cryptographic audit completed.
