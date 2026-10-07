# Portable Enigm SDK

This pre-release adds an Enigm V2 integration profile to the existing low-level API.
It preserves message versions 2/3, attachment version 2, stored session version 5,
identity-binding transcripts, session locators and protocol context strings.
An npm package alone does not supply a messaging service: hosts still provide
transport, authentication, secure persistence and trusted log configuration.

```ts
import {
  createEnigmSessionClient, createEnigmDeviceClient, createEnigmMessageClient,
  createEnigmTransparencyVerifier,
} from '@enigm/crypto/sdk';

const sessions = createEnigmSessionClient({ store: secureStore, randomSource });
const device = createEnigmDeviceClient({ store: deviceKeys, randomSource });
const messages = createEnigmMessageClient({ sessions, device, randomSource, logPublicKey });
const transparency = createEnigmTransparencyVerifier({
  store: secureStore, logPublicKey, origin, witnesses, quorum, fetchConsistencyProof,
});
```

The variables above are host adapters/configuration described in ADAPTERS.md.
All factory methods and input/output types are shipped as TypeScript declarations.
`messages.encryptMessage` constructs content ciphertext and per-device key packets;
`messages.decryptMessage` authenticates attribution and content before committing receive state.
Verify a recipient's public identity and its complete transparency proof with
`transparency.verifyIdentity` before using that identity/bundle as a message target.
Identity binding alone does not prove current active membership or witness quorum.
Use trusted configuration, never log keys supplied in an untrusted message.

`device.openSessionEncodedPending` opens without consuming a one-time key; call
`consumeOpenedSessionKey` only after authenticated receive state has been persisted.
Session methods also expose recovery, transfer state and group epoch operations.
Persist advancement before acknowledging delivery. Retain private prekeys for delayed delivery
according to the application's lifecycle policy. Hosts must serialize complete receive operations
for each local account; individual state transactions alone do not serialize prekey consumption.

```ts
import { encryptEnigmAttachment, decryptEnigmAttachment } from '@enigm/crypto/sdk';
const { encrypted, fileKey } = encryptEnigmAttachment(binaryFile, randomSource);
const recovered = decryptEnigmAttachment(encrypted, fileKey, expectedSha256);
```

Attachments preserve the existing base64-inside-encrypted-payload format and
`enigm-crypto-v2-attachment` context. Send the file key inside an authenticated encrypted
message, never with publicly accessible attachment metadata. Wipe keys and plaintext when done.
Images, audio, video and documents use the same binary attachment API; upload/download and
media presentation remain host responsibilities. Device playback and application integration
have not been verified by these library tests.

See `examples/sdk.ts` for executable attachment and session examples with volatile
in-memory storage; that storage is unsuitable for production secrets. Root exports and original
protocol capabilities remain available; raw source imports are for library development.

Receive sessions now persist an optional `sessionSenders` map alongside existing version-5
state; this does not change ratchet ciphertext or protocol bytes. Established messages must
match the account/device verified during bootstrap, including recovery reads. Old state lacking
this metadata remains readable by the low-level API, but the message SDK fails closed until
an authenticated historical bootstrap is opened and its root matches the stored session.
Retain the relevant prekey material during migration. If it is unavailable, perform an explicit
verified session re-establishment; never infer identity from the untrusted sender label.
`initializeOrVerifySession` accepts optional sender metadata for migration only after the host
has verified the binding and opened the matching authenticated bootstrap root.
