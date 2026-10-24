// Passkeys in the browser. Options come from Warden as JSON (base64url); results go back the same way,
// in the shape py_webauthn verifies. Nothing about the passkey is stored here.

const b64u = {
  decode(s: string): ArrayBuffer {
    const pad = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    const bin = atob(pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  },
  encode(buf: ArrayBuffer | null): string {
    if (!buf) return "";
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
};

type J = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

export class PasskeyCancelled extends Error {}

function wrap(e: unknown): never {
  const name = (e as Error)?.name;
  if (name === "NotAllowedError" || name === "AbortError") throw new PasskeyCancelled("cancelled");
  throw e;
}

export async function getAssertion(options: J, signal?: AbortSignal): Promise<J> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64u.decode(options.challenge),
    rpId: options.rpId,
    timeout: options.timeout,
    userVerification: options.userVerification ?? "required",
    allowCredentials: (options.allowCredentials ?? []).map((c: J) => ({ type: "public-key", id: b64u.decode(c.id), transports: c.transports })),
  };
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.get({ publicKey, signal })) as PublicKeyCredential;
  } catch (e) {
    wrap(e);
  }
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u.encode(r.clientDataJSON),
      authenticatorData: b64u.encode(r.authenticatorData),
      signature: b64u.encode(r.signature),
      userHandle: r.userHandle ? b64u.encode(r.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export async function createCredential(options: J, signal?: AbortSignal): Promise<J> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: b64u.decode(options.challenge),
    rp: options.rp,
    user: { ...options.user, id: b64u.decode(options.user.id) },
    pubKeyCredParams: options.pubKeyCredParams,
    timeout: options.timeout,
    attestation: options.attestation ?? "none",
    authenticatorSelection: options.authenticatorSelection,
    excludeCredentials: (options.excludeCredentials ?? []).map((c: J) => ({ type: "public-key", id: b64u.decode(c.id) })),
  };
  let cred: PublicKeyCredential;
  try {
    cred = (await navigator.credentials.create({ publicKey, signal })) as PublicKeyCredential;
  } catch (e) {
    wrap(e);
  }
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: b64u.encode(cred.rawId),
    type: cred.type,
    response: { clientDataJSON: b64u.encode(r.clientDataJSON), attestationObject: b64u.encode(r.attestationObject) },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
