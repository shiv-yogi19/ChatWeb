// ECDH P-256 -> HKDF-SHA256 -> AES-256-GCM. Envelope v1. AAD binds sender|recipient|message id.
const te = new TextEncoder(), td = new TextDecoder();
const P = { name: "ECDH", namedCurve: "P-256" };
const b64 = (u) => btoa(String.fromCharCode(...new Uint8Array(u)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const pubOnly = (j) => ({ kty: "EC", crv: "P-256", x: j.x, y: j.y });
export async function genKey() {
  const k = await crypto.subtle.generateKey(P, true, ["deriveBits"]);
  return { priv: await crypto.subtle.exportKey("jwk", k.privateKey), pub: pubOnly(await crypto.subtle.exportKey("jwk", k.publicKey)) };
}
export async function fingerprint(j) {
  const d = await crypto.subtle.digest("SHA-256", te.encode(j.x + "." + j.y));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("").slice(0, 32);
}
export async function deriveKey(privJwk, peerPub, myFp) {
  const priv = await crypto.subtle.importKey("jwk", privJwk, P, false, ["deriveBits"]);
  const pub = await crypto.subtle.importKey("jwk", pubOnly(peerPub), P, false, []); // rejects invalid points
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  const info = te.encode("SENDORA-v1|" + [myFp, await fingerprint(peerPub)].sort().join("|"));
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
export async function encrypt(key, text, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad) }, key, te.encode(text));
  return { v: 1, iv: b64(iv), ct: b64(ct) };
}
export async function decrypt(key, env, aad) {
  if (!env || env.v !== 1 || typeof env.iv !== "string" || typeof env.ct !== "string") throw new Error("bad envelope");
  const iv = unb64(env.iv);
  if (iv.length !== 12) throw new Error("bad envelope");
  return td.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: te.encode(aad) }, key, unb64(env.ct)));
}

// Proof of key ownership (see SECURITY.md): HMAC keyed by ECDH(client key, server ephemeral key) over a fresh nonce.
async function hmacKey(privJwk, peerPub) {
  const priv = await crypto.subtle.importKey("jwk", privJwk, P, false, ["deriveBits"]);
  const pub = await crypto.subtle.importKey("jwk", pubOnly(peerPub), P, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, priv, 256);
  return crypto.subtle.importKey("raw", bits, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
export const prove = async (priv, spub, n) => b64(await crypto.subtle.sign("HMAC", await hmacKey(priv, spub), te.encode("SENDORA-auth-v1|" + n)));
export const checkProof = async (spriv, cpub, n, proof) => crypto.subtle.verify("HMAC", await hmacKey(spriv, cpub), unb64(proof), te.encode("SENDORA-auth-v1|" + n));
export const safetyNumber = (a, b) => [a, b].sort().join("").match(/.{1,4}/g).join("-");
export const numbersMatch = (typed, expected) => typed.toLowerCase().replace(/[^0-9a-f]/g, "") === expected.replace(/-/g, "");
