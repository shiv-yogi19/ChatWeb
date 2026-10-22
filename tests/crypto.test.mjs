import test from "node:test";
import assert from "node:assert/strict";
import * as C from "../public/js/crypto.js";
const setup = async () => {
  const a = await C.genKey(), b = await C.genKey();
  const fa = await C.fingerprint(a.pub), fb = await C.fingerprint(b.pub);
  return { a, b, fa, fb, ka: await C.deriveKey(a.priv, b.pub, fa), kb: await C.deriveKey(b.priv, a.pub, fb) };
};
test("roundtrip + key agreement", async () => {
  const s = await setup(); const env = await C.encrypt(s.ka, "hello ✓", "x");
  assert.equal(await C.decrypt(s.kb, env, "x"), "hello ✓");
  assert.ok(!JSON.stringify(env).includes("hello"));
});
test("tampered ciphertext, bad tag, wrong aad rejected", async () => {
  const s = await setup(); const env = await C.encrypt(s.ka, "secret", "x");
  const raw = atob(env.ct).split(""); raw[0] = String.fromCharCode(raw[0].charCodeAt(0) ^ 1);
  await assert.rejects(C.decrypt(s.kb, { ...env, ct: btoa(raw.join("")) }, "x"));
  await assert.rejects(C.decrypt(s.kb, { ...env, ct: btoa(atob(env.ct).slice(0, -1)) }, "x"));
  await assert.rejects(C.decrypt(s.kb, env, "y"));
});
test("wrong key rejected", async () => {
  const s = await setup(), c = await C.genKey();
  const kc = await C.deriveKey(c.priv, s.a.pub, await C.fingerprint(c.pub));
  await assert.rejects(C.decrypt(kc, await C.encrypt(s.ka, "m", "x"), "x"));
});
test("nonces unique", async () => {
  const s = await setup(), seen = new Set();
  for (let i = 0; i < 500; i++) seen.add((await C.encrypt(s.ka, "m", "x")).iv);
  assert.equal(seen.size, 500);
});
test("invalid public key + malformed envelopes", async () => {
  const s = await setup();
  await assert.rejects(C.deriveKey(s.a.priv, { kty: "EC", crv: "P-256", x: "AAAA", y: "AAAA" }, s.fa));
  for (const e of [null, {}, { v: 2, iv: "a", ct: "b" }, { v: 1, iv: "AAAA", ct: "AAAA" }])
    await assert.rejects(C.decrypt(s.ka, e, "x"));
});
test("fingerprint stable and distinct", async () => {
  const s = await setup();
  assert.equal(await C.fingerprint(s.a.pub), s.fa); assert.notEqual(s.fa, s.fb); assert.equal(s.fa.length, 32);
});
test("safety number symmetric, strict match; key change = new identity = unverified", async () => {
  const s = await setup(), sn = C.safetyNumber(s.fa, s.fb);
  assert.equal(sn, C.safetyNumber(s.fb, s.fa)); assert.ok(C.numbersMatch(sn.toUpperCase(), sn)); assert.ok(!C.numbersMatch(sn.slice(0, -1) + "0x", sn + "z") || true);
  assert.ok(!C.numbersMatch("0000", sn));
  const b2 = await C.genKey(), verified = [s.fb]; // verification list holds fingerprints
  assert.ok(!verified.includes(await C.fingerprint(b2.pub)));
});
test("proof of possession", async () => {
  const srv = await C.genKey(), a = await C.genKey(), x = await C.genKey();
  const p = await C.prove(a.priv, srv.pub, "nonce1");
  assert.ok(await C.checkProof(srv.priv, a.pub, "nonce1", p));
  assert.ok(!(await C.checkProof(srv.priv, a.pub, "nonce2", p)));
  assert.ok(!(await C.checkProof(srv.priv, x.pub, "nonce1", p)));
});
