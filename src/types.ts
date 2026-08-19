import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export type FidoAuthenticationMode = "passkey" | "security_key" | "hybrid";
export type FidoEnrollmentMode = "passkey" | "security_key";

export interface ProjectUser {
  uid: string;
  email: string;
  email_verified: boolean;
  status: "active" | "disabled";
  passkey_count: number;
  created_at: string;
}

export interface AuthenticatedSession {
  token: string;
  expiresAt: string;
  projectUser: ProjectUser;
}

export type AuthProgress =
  | {status: "factor_verified"; factor: "password"; expiresAt: string}
  | {status: "authenticated"; session: AuthenticatedSession};

export interface LoginAttempt {
  token: string;
  expiresAt: string;
}

export interface FidoCredential {
  uid: string;
  kind: FidoEnrollmentMode;
  created_at: string;
}

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface ComplicatedAuthClientOptions {
  /** Base URL of the customer-owned BFF, for example `/auth`. */
  baseUrl: string;
  /** Defaults to sessionStorage in a browser and memory storage otherwise. */
  storage?: StorageLike;
  fetch?: typeof globalThis.fetch;
  storageKeyPrefix?: string;
}

export interface PluginRequestOptions {
  method: string;
  auth: "login" | "session";
  body?: BodyInit;
  headers?: HeadersInit;
}

export interface FidoOptionsResponse {
  ceremony_uid: string;
  public_key: PublicKeyCredentialRequestOptionsJSON;
}

export interface FidoEnrollmentOptionsResponse {
  ceremony_uid: string;
  public_key: PublicKeyCredentialCreationOptionsJSON;
}

export interface SessionWireResponse {
  session_token: string;
  expires_at: string;
  project_user: ProjectUser;
}
