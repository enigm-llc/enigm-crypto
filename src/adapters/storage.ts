/** Secure host storage. Writes must be atomic; exclusive must serialize by account
 * across all SDK clients sharing this storage, including processes when applicable. */
export interface SecureStateStore {
  read(accountId: string): Promise<string | null>;
  write(accountId: string, serialized: string): Promise<void>;
  delete(accountId: string): Promise<void>;
  exclusive<T>(accountId: string, operation: () => Promise<T>): Promise<T>;
}
