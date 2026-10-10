import type { SecureStateStore } from '@enigm/crypto/sdk';

/** Demonstration only: volatile plaintext records, no hardware access controls. */
export const createDemoStore = (): SecureStateStore => {
  const rows = new Map<string, string>();
  const queues = new Map<string, Promise<unknown>>();
  return {
    read: id => Promise.resolve(rows.get(id) ?? null),
    write: (id, value) => { rows.set(id, value); return Promise.resolve(); },
    delete: id => { rows.delete(id); return Promise.resolve(); },
    exclusive: <T>(id: string, action: () => Promise<T>): Promise<T> => {
      const operation = (queues.get(id) ?? Promise.resolve()).catch(() => {}).then(action);
      queues.set(id, operation);
      const cleanup = () => { if (queues.get(id) === operation) queues.delete(id); };
      void operation.then(cleanup, cleanup);
      return operation;
    },
  };
};
