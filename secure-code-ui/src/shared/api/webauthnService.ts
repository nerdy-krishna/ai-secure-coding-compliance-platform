// secure-code-ui/src/shared/api/webauthnService.ts
//
// Browser-side WebAuthn helpers wired to the SCCAP backend at
// /api/v1/auth/webauthn/{register,login}/{begin,finish} +
// /api/v1/auth/webauthn/credentials.
//
// The backend serialises PublicKeyCredentialCreationOptions /
// PublicKeyCredentialRequestOptions via py_webauthn's options_to_json,
// which emits base64url strings for every binary field. The browser
// WebAuthn API needs ArrayBuffers in those slots, so this module:
//   1. Decodes the server-emitted base64url strings into ArrayBuffers
//      before handing the options to navigator.credentials.{create,get}.
//   2. Re-encodes the resulting credential's binary fields back to
//      base64url strings before POSTing the response.
//
// All network calls go through the shared apiClient so the bearer token
// is attached automatically when present.

import apiClient from "./apiClient";

export interface PasskeySummary {
  id: string;                   // backend UUID
  friendly_name: string;
  transports: string[];
  created_at: string | null;
  last_used_at: string | null;
}

// ----- base64url helpers ----------------------------------------------------

function base64urlToArrayBuffer(s: string): ArrayBuffer {
  // base64url -> base64 -> binary string -> Uint8Array.
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ----- options decoders ----------------------------------------------------

interface ServerCreateOptions {
  challenge: string;
  rp: PublicKeyCredentialRpEntity;
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: { id: string; type: "public-key"; transports?: AuthenticatorTransport[] }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  // backend tags the friendly_name back so we don't have to thread it
  // separately through the call site
  _friendly_name?: string;
}

interface ServerRequestOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: { id: string; type: "public-key"; transports?: AuthenticatorTransport[] }[];
  userVerification?: UserVerificationRequirement;
}

function decodeCreateOptions(o: ServerCreateOptions): PublicKeyCredentialCreationOptions {
  return {
    challenge: base64urlToArrayBuffer(o.challenge),
    rp: o.rp,
    user: {
      id: base64urlToArrayBuffer(o.user.id),
      name: o.user.name,
      displayName: o.user.displayName,
    },
    pubKeyCredParams: o.pubKeyCredParams,
    timeout: o.timeout,
    excludeCredentials: o.excludeCredentials?.map((c) => ({
      id: base64urlToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports,
    })),
    authenticatorSelection: o.authenticatorSelection,
    attestation: o.attestation,
  };
}

function decodeRequestOptions(o: ServerRequestOptions): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64urlToArrayBuffer(o.challenge),
    timeout: o.timeout,
    rpId: o.rpId,
    allowCredentials: o.allowCredentials?.map((c) => ({
      id: base64urlToArrayBuffer(c.id),
      type: c.type,
      transports: c.transports,
    })),
    userVerification: o.userVerification,
  };
}

// ----- credential -> JSON encoders ------------------------------------------

function encodeRegistrationCredential(cred: PublicKeyCredential): Record<string, unknown> {
  const att = cred.response as AuthenticatorAttestationResponse;
  // Some browsers don't expose getTransports(); guard it.
  const transports =
    typeof att.getTransports === "function" ? att.getTransports() : undefined;
  return {
    id: cred.id,
    rawId: arrayBufferToBase64url(cred.rawId),
    type: cred.type,
    transports,
    response: {
      attestationObject: arrayBufferToBase64url(att.attestationObject),
      clientDataJSON: arrayBufferToBase64url(att.clientDataJSON),
      transports,
    },
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  };
}

function encodeAuthenticationCredential(cred: PublicKeyCredential): Record<string, unknown> {
  const ass = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: arrayBufferToBase64url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: arrayBufferToBase64url(ass.authenticatorData),
      clientDataJSON: arrayBufferToBase64url(ass.clientDataJSON),
      signature: arrayBufferToBase64url(ass.signature),
      userHandle: ass.userHandle ? arrayBufferToBase64url(ass.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
  };
}

// ----- public API -----------------------------------------------------------

export const webauthnService = {
  isSupported(): boolean {
    return (
      typeof window !== "undefined" &&
      typeof window.PublicKeyCredential !== "undefined" &&
      typeof navigator !== "undefined" &&
      !!navigator.credentials
    );
  },

  /** List the current user's registered passkeys. */
  async list(): Promise<PasskeySummary[]> {
    const r = await apiClient.get<PasskeySummary[]>("/auth/webauthn/credentials");
    return r.data;
  },

  /** Delete a passkey by its backend UUID. */
  async remove(id: string): Promise<void> {
    await apiClient.delete(`/auth/webauthn/credentials/${id}`);
  },

  /**
   * Full register-passkey ceremony. Calls /register/begin → invokes
   * navigator.credentials.create() → POSTs the result to /register/finish.
   * Returns the persisted passkey row as the backend echoes it.
   */
  async register(friendlyName: string): Promise<{ id: string; friendly_name: string }> {
    if (!this.isSupported()) throw new Error("WebAuthn not supported in this browser");
    const begin = await apiClient.post<ServerCreateOptions>(
      "/auth/webauthn/register/begin",
      { friendly_name: friendlyName },
    );
    const options = decodeCreateOptions(begin.data);
    const cred = (await navigator.credentials.create({ publicKey: options })) as
      | PublicKeyCredential
      | null;
    if (!cred) throw new Error("authenticator returned no credential");
    const finish = await apiClient.post<{
      id: string;
      friendly_name: string;
      credential_id_b64: string;
    }>("/auth/webauthn/register/finish", {
      friendly_name: friendlyName,
      credential: encodeRegistrationCredential(cred),
    });
    return finish.data;
  },

  /**
   * Full passkey-login ceremony for a given email. Calls /login/begin
   * → invokes navigator.credentials.get() → POSTs to /login/finish.
   * Returns { access_token, token_type } on success; the caller stores
   * the token via AuthProvider.loginWithAccessToken().
   */
  async login(email: string): Promise<{ access_token: string; token_type: string }> {
    if (!this.isSupported()) throw new Error("WebAuthn not supported in this browser");
    const begin = await apiClient.post<ServerRequestOptions>(
      "/auth/webauthn/login/begin",
      { email },
    );
    const options = decodeRequestOptions(begin.data);
    const cred = (await navigator.credentials.get({ publicKey: options })) as
      | PublicKeyCredential
      | null;
    if (!cred) throw new Error("authenticator returned no assertion");
    const finish = await apiClient.post<{ access_token: string; token_type: string }>(
      "/auth/webauthn/login/finish",
      { credential: encodeAuthenticationCredential(cred) },
    );
    return finish.data;
  },
};

export default webauthnService;
