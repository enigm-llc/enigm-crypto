import test from "node:test";
import assert from "node:assert/strict";
import { generateIdentity, signHybrid } from "../src/primitives/index.ts";
test("explicit signing entropy preserves the curve blinding CSPRNG requirement", () => {
  const entropy = (length: number) => new Uint8Array(length).fill(12);
  const identity = generateIdentity(entropy);
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  try {
    Object.defineProperty(globalThis, "crypto", {
      value: undefined,
      configurable: true,
    });
    const message = Uint8Array.of(1, 2);
    assert.throws(
      () => signHybrid(identity, message, entropy),
      /getRandomValues/
    );
  } finally {
    if (descriptor) Object.defineProperty(globalThis, "crypto", descriptor);
  }
});

test("signing validates the supplied entropy length", () => {
  const identity = generateIdentity((length: number) =>
    new Uint8Array(length).fill(9)
  );
  assert.throws(
    () => signHybrid(identity, Uint8Array.of(1), () => new Uint8Array(1)),
    /entropy/
  );
});
