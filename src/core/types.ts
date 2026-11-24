export const PROTOCOL_VERSION = 2 as const;

export const CIPHER_SUITE =
  'ENIGM-PQ-V2-MLKEM768-X25519-MLDSA65-ED25519-AES256GCM-HKDFSHA512' as const;

export type CipherSuite = typeof CIPHER_SUITE;
export type RandomSource = (length: number) => Uint8Array;

export type PublicIdentity = {
  version: typeof PROTOCOL_VERSION;
  suite: CipherSuite;
  keyId: Uint8Array;
  mlDsaPublicKey: Uint8Array;
  ed25519PublicKey: Uint8Array;
};

/**
 * Private keys are stored as seeds: `mlDsaSeed` is the 32-byte FIPS 204 ξ and
 * `ed25519SecretKey` the 32-byte RFC 8032 seed. Expanded ML-DSA keys are not accepted.
 */
export type PrivateIdentity = PublicIdentity & {
  mlDsaSeed: Uint8Array;
  ed25519SecretKey: Uint8Array;
};

export type PublicKemBundle = {
  version: typeof PROTOCOL_VERSION;
  suite: CipherSuite;
  keyId: Uint8Array;
  mlKemPublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  identityKeyId: Uint8Array;
  expiresAt: number;
  signature: HybridSignature;
};

/**
 * `mlKemSeed` is the 64-byte FIPS 203 seed `d‖z`; `x25519SecretKey` the 32-byte RFC 7748
 * scalar. Expanded (2400-byte) ML-KEM decapsulation keys are not accepted.
 */
export type PrivateKemBundle = PublicKemBundle & {
  mlKemSeed: Uint8Array;
  x25519SecretKey: Uint8Array;
};

export type HybridSignature = {
  mlDsa: Uint8Array;
  ed25519: Uint8Array;
};

export type HybridEnvelope = {
  version: typeof PROTOCOL_VERSION;
  suite: CipherSuite;
  senderIdentityKeyId: Uint8Array;
  recipientKemKeyId: Uint8Array;
  mlKemCiphertext: Uint8Array;
  ephemeralX25519PublicKey: Uint8Array;
  nonce: Uint8Array;
  createdAt: number;
  ciphertext: Uint8Array;
  supplementalSecretUsed: boolean;
  signature: HybridSignature;
};

export type SealOptions = {
  sender: PrivateIdentity;
  recipientIdentity: PublicIdentity;
  recipient: PublicKemBundle;
  plaintext: Uint8Array;
  context: Uint8Array;
  now?: number;
  supplementalSecret?: Uint8Array;
  randomSource?: RandomSource;
};

export type OpenOptions = {
  sender: PublicIdentity;
  recipientIdentity: PublicIdentity;
  recipient: PrivateKemBundle;
  envelope: HybridEnvelope;
  context: Uint8Array;
  now?: number;
  supplementalSecret?: Uint8Array;
};

export type SealedSenderEnvelope = {
  version: typeof PROTOCOL_VERSION;
  suite: CipherSuite;
  recipientKemKeyId: Uint8Array;
  mlKemCiphertext: Uint8Array;
  ephemeralX25519PublicKey: Uint8Array;
  nonce: Uint8Array;
  createdAt: number;
  ciphertext: Uint8Array;
  supplementalSecretUsed: boolean;
};

export type SealSenderOptions = {
  sender: PrivateIdentity;
  recipientIdentity: PublicIdentity;
  recipient: PublicKemBundle;
  plaintext: Uint8Array;
  context: Uint8Array;
  now?: number;
  supplementalSecret?: Uint8Array;
  randomSource?: RandomSource;
};

export type OpenSealedSenderOptions = {
  recipientIdentity: PublicIdentity;
  recipient: PrivateKemBundle;
  envelope: SealedSenderEnvelope;
  context: Uint8Array;
  expectedSenderIdentity?: PublicIdentity;
  now?: number;
  supplementalSecret?: Uint8Array;
};

export type OpenedSealedSender = {
  sender: PublicIdentity;
  plaintext: Uint8Array;
};

export type ChainState = {
  version: typeof PROTOCOL_VERSION;
  chainId: Uint8Array;
  counter: number;
  chainKey: Uint8Array;
};

export type SkippedMessageKey = {
  chainId: Uint8Array;
  counter: number;
  messageKey: Uint8Array;
};

export type SessionRole = 'initiator' | 'responder';

export type SessionState = {
  version: typeof PROTOCOL_VERSION;
  sessionId: Uint8Array;
  epoch: number;
  rootKey: Uint8Array;
  send: ChainState;
  receive: ChainState;
  skipped: SkippedMessageKey[];
};

export type GroupEpochState = {
  version: typeof PROTOCOL_VERSION;
  groupId: Uint8Array;
  epoch: number;
  epochSecret: Uint8Array;
  membersHash: Uint8Array;
};

export interface SecureKeyStore {
  load(accountScope: string, keyId: Uint8Array): Promise<Uint8Array | null>;
  save(accountScope: string, keyId: Uint8Array, sealedKeyMaterial: Uint8Array): Promise<void>;
  remove(accountScope: string, keyId: Uint8Array): Promise<void>;
}
