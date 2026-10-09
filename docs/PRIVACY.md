# Privacy and participant anonymity

## Goals and present guarantees

This library protects encrypted content and authenticates cryptographic identities and protocol
state. Hiding participant relationships from service operators is a separate product/transport goal,
outside this encryption library release. This library supplies cryptographic building blocks; the existing
Enigm V2 message SDK protects content but does not achieve server-blind participant anonymity.
It is not a zero-knowledge proof system, anonymity network or private contact-discovery service.

| Information | Existing library/profile behavior |
| --- | --- |
| Message and attachment plaintext | Encrypted under endpoint-held keys; the host must never upload those keys or plaintext |
| SDK sender/recipient account and device identifiers | Present outside content ciphertext in message key packets |
| SDK session identifier | Stable per conversation/device direction; linkable, and derivable when identifiers are known |
| Bootstrap identity and signed account/device binding | Visible in the existing SDK profile; the signing authority knows the mapping |
| Public transparency entries | Opaque commitments; privacy depends on unpredictable inputs or secret domain-separated commitment keys |
| Low-level sender-sealed identity | Inside recipient-only ciphertext; routing, recipient key identifier, time and size remain visible |
| IP, timing, file sizes, push, payment and authorization metadata | Controlled by host/provider protocols, not hidden by this library |
| Recovery and device-transfer state | Sensitive endpoint material; exposure may reveal historical content and relationships |

Pseudonymous identifiers are still identifiers. Hashing an account/device tuple does not make
it unlinkable or protect low-entropy identifiers from enumeration. A public opaque log also does
not prevent the private identity-binding service from knowing account/device mappings.

## Data minimization

The runtime includes no analytics, telemetry, embedded service URL, credential, filesystem client
or logging of message content. A supplied transport adapter may make network requests, and a
supplied storage adapter may persist sensitive records. Applications must review those adapters,
request headers, error reporting, crash dumps, notification services and backup policies separately.

The SDK requires local account/device identifiers for isolation and verification. Do not place
real names, contact addresses or provider identities in identifiers or associated data. Do not log
serialized state, recovery capsules, keys, message contents or identity lookup responses. The
library does not enforce a product's retention policy or guarantee deletion from recipients/backups.

## What server-blind participation would require

A separately designed and reviewed protocol needs private identity/contact discovery, credentials
that admit delivery without exposing account identity, unlinkable recipient routing, encrypted
participant metadata and group fan-out, and network/traffic protections with explicit adversary
assumptions. Authorization, abuse handling, notifications, recovery and deletion must be redesigned
consistently around those capabilities. Applying `sealSender` to content alone does not provide them.

Those changes would require a versioned protocol and coordinated host/server integration. Existing
V2 message bytes and attribution checks are preserved in this release. Do not advertise the current
SDK as hiding participant relationships from the server.
