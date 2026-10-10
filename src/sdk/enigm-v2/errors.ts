export class KeyTransparencyErrorEnigmV2 extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "KeyTransparencyErrorEnigmV2";
  }
}
