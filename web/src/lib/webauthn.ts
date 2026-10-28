// Converts between the server's WebAuthn JSON (base64url) and the browser's
// credential API (ArrayBuffers) for passkeys (M11).

function fromB64url(s: string): ArrayBuffer {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "="));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function toB64url(buf: ArrayBuffer | null): string {
  if (!buf) return "";
  let s = "";
  for (const c of new Uint8Array(buf)) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type Json = Record<string, unknown>;

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && !!navigator.credentials;
}

/** createPasskey runs navigator.credentials.create with server options. */
export async function createPasskey(options: { publicKey: Json }): Promise<Json> {
  const pk = options.publicKey;
  const user = pk.user as Json;
  const publicKey = {
    ...pk,
    challenge: fromB64url(pk.challenge as string),
    user: { ...user, id: fromB64url(user.id as string) },
    excludeCredentials: ((pk.excludeCredentials as Json[] | undefined) ?? []).map((c) => ({ ...c, id: fromB64url(c.id as string) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created.");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: { clientDataJSON: toB64url(r.clientDataJSON), attestationObject: toB64url(r.attestationObject), transports: r.getTransports?.() ?? [] },
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** getPasskey runs navigator.credentials.get with server options. */
export async function getPasskey(options: { publicKey: Json }): Promise<Json> {
  const pk = options.publicKey;
  const publicKey = {
    ...pk,
    challenge: fromB64url(pk.challenge as string),
    allowCredentials: ((pk.allowCredentials as Json[] | undefined) ?? []).map((c) => ({ ...c, id: fromB64url(c.id as string) })),
  } as unknown as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was used.");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    response: { clientDataJSON: toB64url(r.clientDataJSON), authenticatorData: toB64url(r.authenticatorData), signature: toB64url(r.signature), userHandle: toB64url(r.userHandle) },
    authenticatorAttachment: cred.authenticatorAttachment,
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export const __test = { fromB64url, toB64url };
