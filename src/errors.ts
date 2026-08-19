export type ComplicatedAuthErrorKind = "api" | "network" | "state" | "webauthn";

export class ComplicatedAuthError extends Error {
  constructor(
    message: string,
    public readonly kind: ComplicatedAuthErrorKind,
    public readonly code: string,
    public readonly status?: number,
    public override readonly cause?: unknown,
  ) {
    super(message);
    this.name = "ComplicatedAuthError";
  }
}
