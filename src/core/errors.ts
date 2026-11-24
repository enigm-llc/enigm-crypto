/**
 * Stored private key material cannot be used.
 * - `KEY_FORMAT_CHANGED`: the key predates the seed format (or is malformed). There is no
 *   migration: discard it and generate new identity/KEM keys.
 * - `KEY_MISMATCH`: the seed does not derive the stored public key (corruption or tampering).
 */
export type EnigmKeyErrorCode = 'KEY_FORMAT_CHANGED' | 'KEY_MISMATCH';

export class EnigmKeyError extends Error {
  constructor(
    public readonly code: EnigmKeyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'EnigmKeyError';
  }
}
