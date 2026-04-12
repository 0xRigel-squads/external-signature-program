export class ExternalSignatureSdkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExternalSignatureSdkError";
  }
}

export function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new ExternalSignatureSdkError(message);
  }
}
