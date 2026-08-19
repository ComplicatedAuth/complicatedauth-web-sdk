import {beforeEach, describe, expect, it, vi} from "vitest";
import {MemoryStorage} from "../src/storage.js";

const {startAuthentication, startRegistration} = vi.hoisted(() => ({
  startAuthentication: vi.fn(),
  startRegistration: vi.fn(),
}));
vi.mock("@simplewebauthn/browser", () => ({
  browserSupportsWebAuthn: () => true,
  browserSupportsWebAuthnAutofill: async () => true,
  platformAuthenticatorIsAvailable: async () => true,
  startAuthentication,
  startRegistration,
}));

import {ComplicatedAuthClient} from "../src/client.js";

function json(value: unknown, status = 200): Response {
  return new Response(status === 204 ? null : JSON.stringify(value), {
    status,
    headers: {"Content-Type": "application/json"},
  });
}

describe("ComplicatedAuthClient", () => {
  beforeEach(() => vi.clearAllMocks());

  it("keeps a login attempt and completes security-key authentication", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(json({login_attempt: "login-1", expires_at: "2030-01-01T00:00:00Z"}))
      .mockResolvedValueOnce(json({ceremony_uid: "ceremony-1", public_key: {challenge: "abc"}}))
      .mockResolvedValueOnce(json({
        session_token: "session-1",
        expires_at: "2030-02-01T00:00:00Z",
        project_user: {uid: "user-1", email: "a@example.com", email_verified: true, status: "active", passkey_count: 1, created_at: "2029-01-01T00:00:00Z"},
      }));
    startAuthentication.mockResolvedValue({id: "credential-1"});
    const client = new ComplicatedAuthClient({baseUrl: "/auth", fetch: fetcher, storage: new MemoryStorage()});

    await client.startLogin("a@example.com");
    const session = await client.startSecurityKeyAuth();

    expect(session.token).toBe("session-1");
    expect(startAuthentication).toHaveBeenCalledWith({optionsJSON: {challenge: "abc"}});
    expect(fetcher.mock.calls[1]?.[1]?.headers.get("X-ComplicatedAuth-Login")).toBe("login-1");
    expect(fetcher.mock.calls[2]?.[1]?.body).toContain('"mode":"security_key"');
  });

  it("persists a verified password factor without inventing a session", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(json({login_attempt: "login-1", expires_at: "2030-01-01T00:00:00Z"}))
      .mockResolvedValueOnce(json({status: "factor_verified", factor: "password", expires_at: "2030-01-01T00:05:00Z"}));
    const client = new ComplicatedAuthClient({baseUrl: "/auth", fetch: fetcher, storage: new MemoryStorage()});
    await client.startLogin("a@example.com");
    await expect(client.startPasswordAuth("secret")).resolves.toEqual({
      status: "factor_verified",
      factor: "password",
      expiresAt: "2030-01-01T00:05:00Z",
    });
    expect(client.getSession()).toBeNull();
  });

  it("enrolls a first passkey through the password-verified login attempt", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(json({login_attempt: "login-1", expires_at: "2030-01-01T00:00:00Z"}))
      .mockResolvedValueOnce(json({status: "factor_verified", factor: "password", expires_at: "2030-01-01T00:05:00Z"}))
      .mockResolvedValueOnce(json({ceremony_uid: "ceremony-1", public_key: {challenge: "abc", user: {id: "user"}}}))
      .mockResolvedValueOnce(json({
        session_token: "session-1",
        expires_at: "2030-02-01T00:00:00Z",
        project_user: {uid: "user-1", email: "a@example.com", email_verified: true, status: "active", passkey_count: 1, created_at: "2029-01-01T00:00:00Z"},
      }));
    startRegistration.mockResolvedValue({id: "credential-1"});
    const client = new ComplicatedAuthClient({baseUrl: "/auth", fetch: fetcher, storage: new MemoryStorage()});

    await client.startLogin("a@example.com");
    await client.startPasswordAuth("secret");
    const session = await client.startFirstPasskeyEnrollment();

    expect(session.token).toBe("session-1");
    expect(startRegistration).toHaveBeenCalledWith({optionsJSON: {challenge: "abc", user: {id: "user"}}});
    expect(fetcher.mock.calls[2]?.[0]).toBe("/auth/login/fido/enrollment/options");
    expect(fetcher.mock.calls[3]?.[1]?.body).toContain('"mode":"passkey"');
  });
});
