import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  platformAuthenticatorIsAvailable,
  startAuthentication as startWebAuthnAuthentication,
  startRegistration as startWebAuthnRegistration,
} from "@simplewebauthn/browser";
import {ComplicatedAuthError} from "./errors.js";
import {defaultStorage} from "./storage.js";
import type {
  AuthProgress,
  AuthenticatedSession,
  ComplicatedAuthClientOptions,
  FidoAuthenticationMode,
  FidoCredential,
  FidoEnrollmentMode,
  FidoEnrollmentOptionsResponse,
  FidoOptionsResponse,
  LoginAttempt,
  ProjectUser,
  PluginRequestOptions,
  SessionWireResponse,
  StorageLike,
} from "./types.js";

interface ErrorEnvelope {
  error?: {code?: string; message?: string; request_id?: string};
}

interface FactorWireResponse {
  status: "factor_verified";
  factor: "password";
  expires_at: string;
}

interface StoredState {
  loginAttempt?: LoginAttempt;
  session?: AuthenticatedSession;
}

export class ComplicatedAuthClient {
  private readonly baseUrl: string;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly storage: StorageLike;
  private readonly stateKey: string;

  constructor(options: ComplicatedAuthClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    if (!this.baseUrl) throw new ComplicatedAuthError("baseUrl is required", "state", "invalid_configuration");
    this.fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!this.fetcher) throw new ComplicatedAuthError("fetch is unavailable", "state", "fetch_unavailable");
    this.storage = options.storage ?? defaultStorage();
    this.stateKey = `${options.storageKeyPrefix ?? "complicatedauth"}:state`;
  }

  async startLogin(email: string): Promise<LoginAttempt> {
    const value = await this.request<{login_attempt: string; expires_at: string}>("/login/start", {
      method: "POST",
      body: {email},
    });
    const attempt = {token: value.login_attempt, expiresAt: value.expires_at};
    this.writeState({...this.readState(), loginAttempt: attempt});
    return attempt;
  }

  async startPasswordAuth(password: string): Promise<AuthProgress> {
    const result = await this.request<FactorWireResponse | SessionWireResponse>("/login/password", {
      method: "POST",
      login: true,
      body: {password},
    });
    if ("session_token" in result) return {status: "authenticated", session: this.acceptSession(result)};
    return {status: "factor_verified", factor: result.factor, expiresAt: result.expires_at};
  }

  startPasskeyAuth(): Promise<AuthenticatedSession> {
    return this.startFidoAuth("passkey");
  }

  startSecurityKeyAuth(): Promise<AuthenticatedSession> {
    return this.startFidoAuth("security_key");
  }

  startHybridAuth(): Promise<AuthenticatedSession> {
    return this.startFidoAuth("hybrid");
  }

  /** Enroll the user's first passkey after password verification and complete login. */
  startFirstPasskeyEnrollment(): Promise<AuthenticatedSession> {
    return this.startFirstFidoEnrollment("passkey");
  }

  /** Enroll the user's first attested security key after password verification and complete login. */
  startFirstSecurityKeyEnrollment(): Promise<AuthenticatedSession> {
    return this.startFirstFidoEnrollment("security_key");
  }

  startPasskeyEnrollment(): Promise<FidoCredential> {
    return this.startFidoEnrollment("passkey");
  }

  startSecurityKeyEnrollment(): Promise<FidoCredential> {
    return this.startFidoEnrollment("security_key");
  }

  async removeFidoCredential(credentialUid: string): Promise<void> {
    await this.request<void>(`/enrollments/fido/${encodeURIComponent(credentialUid)}`, {
      method: "DELETE",
      session: true,
    });
  }

  async restoreSession(): Promise<AuthenticatedSession | null> {
    const current = this.readState().session;
    if (!current) return null;
    try {
      const wire = await this.request<SessionWireResponse>("/session", {method: "GET", session: true});
      return this.acceptSession(wire);
    } catch (error) {
      if (error instanceof ComplicatedAuthError && error.status === 401) {
        this.clearSession();
        return null;
      }
      throw error;
    }
  }

  getSession(): AuthenticatedSession | null {
    return this.readState().session ?? null;
  }

  async logout(): Promise<void> {
    const hasSession = Boolean(this.readState().session);
    try {
      if (hasSession) await this.request<void>("/logout", {method: "POST", session: true});
    } finally {
      this.writeState({});
    }
  }

  cancelLogin(): void {
    const state = this.readState();
    delete state.loginAttempt;
    this.writeState(state);
  }

  /** Transport hook for official ComplicatedAuth browser extensions. */
  async requestPlugin<T>(path: string, options: PluginRequestOptions): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    const state = this.readState();
    if (options.auth === "login") {
      if (!state.loginAttempt) throw new ComplicatedAuthError("Start login first", "state", "login_not_started");
      headers.set("X-ComplicatedAuth-Login", state.loginAttempt.token);
    } else {
      if (!state.session) throw new ComplicatedAuthError("An authenticated session is required", "state", "session_required");
      headers.set("Authorization", `Bearer ${state.session.token}`);
    }
    let response: Response;
    try {
      const init: RequestInit = {method: options.method, headers, cache: "no-store"};
      if (options.body !== undefined) init.body = options.body;
      response = await this.fetcher(`${this.baseUrl}${path}`, init);
    } catch (cause) {
      throw new ComplicatedAuthError("Unable to reach the authentication service", "network", "network_error", undefined, cause);
    }
    if (!response.ok) {
      const value = (await response.json().catch(() => null)) as ErrorEnvelope | null;
      throw new ComplicatedAuthError(
        value?.error?.message ?? "Authentication request failed",
        "api",
        value?.error?.code ?? "request_failed",
        response.status,
      );
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  /** Accept an authenticated session returned by an official extension. */
  acceptPluginSession(wire: SessionWireResponse): AuthenticatedSession {
    return this.acceptSession(wire);
  }

  supportsWebAuthn(): boolean {
    return browserSupportsWebAuthn();
  }

  supportsWebAuthnAutofill(): Promise<boolean> {
    return browserSupportsWebAuthnAutofill();
  }

  platformAuthenticatorAvailable(): Promise<boolean> {
    return platformAuthenticatorIsAvailable();
  }

  private async startFidoAuth(mode: FidoAuthenticationMode): Promise<AuthenticatedSession> {
    try {
      const options = await this.request<FidoOptionsResponse>("/login/fido/options", {
        method: "POST",
        login: true,
        body: {mode},
      });
      const credential = await startWebAuthnAuthentication({optionsJSON: options.public_key});
      const session = await this.request<SessionWireResponse>("/login/fido/verify", {
        method: "POST",
        login: true,
        body: {mode, ceremony_uid: options.ceremony_uid, credential},
      });
      return this.acceptSession(session);
    } catch (error) {
      throw this.wrapWebAuthnError(error);
    }
  }

  private async startFidoEnrollment(mode: FidoEnrollmentMode): Promise<FidoCredential> {
    try {
      const options = await this.request<FidoEnrollmentOptionsResponse>("/enrollments/fido/options", {
        method: "POST",
        session: true,
        body: {mode},
      });
      const credential = await startWebAuthnRegistration({optionsJSON: options.public_key});
      return await this.request<FidoCredential>("/enrollments/fido/verify", {
        method: "POST",
        session: true,
        body: {mode, ceremony_uid: options.ceremony_uid, credential},
      });
    } catch (error) {
      throw this.wrapWebAuthnError(error);
    }
  }

  private async startFirstFidoEnrollment(mode: FidoEnrollmentMode): Promise<AuthenticatedSession> {
    try {
      const options = await this.request<FidoEnrollmentOptionsResponse>("/login/fido/enrollment/options", {
        method: "POST",
        login: true,
        body: {mode},
      });
      const credential = await startWebAuthnRegistration({optionsJSON: options.public_key});
      const session = await this.request<SessionWireResponse>("/login/fido/enrollment/verify", {
        method: "POST",
        login: true,
        body: {mode, ceremony_uid: options.ceremony_uid, credential},
      });
      return this.acceptSession(session);
    } catch (error) {
      throw this.wrapWebAuthnError(error);
    }
  }

  private acceptSession(wire: SessionWireResponse): AuthenticatedSession {
    const session = {token: wire.session_token, expiresAt: wire.expires_at, projectUser: wire.project_user};
    this.writeState({session});
    return session;
  }

  private clearSession(): void {
    const state = this.readState();
    delete state.session;
    this.writeState(state);
  }

  private async request<T>(
    path: string,
    options: {method: string; body?: unknown; login?: boolean; session?: boolean},
  ): Promise<T> {
    const headers = new Headers({Accept: "application/json"});
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(options.body);
    }
    const state = this.readState();
    if (options.login) {
      if (!state.loginAttempt) throw new ComplicatedAuthError("Start login first", "state", "login_not_started");
      headers.set("X-ComplicatedAuth-Login", state.loginAttempt.token);
    }
    if (options.session) {
      if (!state.session) throw new ComplicatedAuthError("An authenticated session is required", "state", "session_required");
      headers.set("Authorization", `Bearer ${state.session.token}`);
    }
    let response: Response;
    try {
      const init: RequestInit = {method: options.method, headers, cache: "no-store"};
      if (body !== undefined) init.body = body;
      response = await this.fetcher(`${this.baseUrl}${path}`, init);
    } catch (cause) {
      throw new ComplicatedAuthError("Unable to reach the authentication service", "network", "network_error", undefined, cause);
    }
    if (!response.ok) {
      const value = (await response.json().catch(() => null)) as ErrorEnvelope | null;
      throw new ComplicatedAuthError(
        value?.error?.message ?? "Authentication request failed",
        "api",
        value?.error?.code ?? "request_failed",
        response.status,
      );
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  private wrapWebAuthnError(error: unknown): unknown {
    if (error instanceof ComplicatedAuthError) return error;
    if (error instanceof Error) return new ComplicatedAuthError(error.message, "webauthn", "webauthn_failed", undefined, error);
    return error;
  }

  private readState(): StoredState {
    const raw = this.storage.getItem(this.stateKey);
    if (!raw) return {};
    try {
      return JSON.parse(raw) as StoredState;
    } catch {
      this.storage.removeItem(this.stateKey);
      return {};
    }
  }

  private writeState(state: StoredState): void {
    if (!state.loginAttempt && !state.session) this.storage.removeItem(this.stateKey);
    else this.storage.setItem(this.stateKey, JSON.stringify(state));
  }
}

export type {ProjectUser};
