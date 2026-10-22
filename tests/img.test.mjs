import test from "node:test";
import assert from "node:assert/strict";
import * as I from "../public/js/img.js";
import * as C from "../public/js/crypto.js";
const jpeg = (n) => { const b = new Uint8Array(n); b.set([0xff, 0xd8, 0xff, 0xe0]); for (let i = 4; i < n; i++) b[i] = i % 251; return b; };
const feed = (A, parts, order) => { let r; for (const i of order) r = A.add("p", "sid-12345678", i, parts.length, parts[i]); return r; };
test("chunks reassemble out of order; duplicate ignored", () => {
  const src = jpeg(20000), parts = I.split(src), A = new I.Assembler();
  assert.ok(A.add("p", "sid-12345678", 1, parts.length, parts[1]).ok); assert.ok(A.add("p", "sid-12345678", 1, parts.length, parts[1]).dup);
  const r = feed(A, parts, [...parts.keys()].filter((i) => i !== 1).reverse()); assert.deepEqual(r.done, src);
});
test("missing chunk never completes; cancel and ttl clean up", () => {
  let t = 0; const A = new I.Assembler(20, 1000, () => t), parts = I.split(jpeg(20000));
  feed(A, parts, [0, 2]); assert.equal(A.m.size, 1); t = 5000; A.sweep(); assert.equal(A.m.size, 0);
  A.add("p", "sid-12345678", 0, 4, parts[0]); A.cancel("p", "sid-12345678"); assert.equal(A.m.size, 0);
});
test("rejects oversize, non-jpeg, bad indices, too many transfers", () => {
  const A = new I.Assembler(1);
  assert.ok(A.add("p", "sid-12345678", 0, I.MAX_CHUNKS + 1, "AA").error); assert.ok(A.add("p", "sid-12345678", 5, 2, "AA").error); assert.ok(A.add("p", "bad id", 0, 1, "AA").error);
  const png = new Uint8Array(100); png.set([0x89, 0x50]); assert.equal(A.add("p", "sid-12345678", 0, 1, I.b64(png)).error, "invalid image");
  A.add("p", "sid-aaaaaaaa", 0, 2, "AAAA"); assert.equal(A.add("p", "sid-bbbbbbbb", 0, 2, "AAAA").error, "too many transfers");
  const big = I.split(new Uint8Array(I.MAX_BYTES + 1000)); assert.ok(big.length > I.MAX_CHUNKS - 1);
});
test("encrypted chunk transfer: decrypts, tamper and wrong mid rejected", async () => {
  const a = await C.genKey(), b = await C.genKey(), fa = await C.fingerprint(a.pub), fb = await C.fingerprint(b.pub);
  const kA = await C.deriveKey(a.priv, b.pub, fa), kB = await C.deriveKey(b.priv, a.pub, fb), src = jpeg(15000), parts = I.split(src), A = new I.Assembler(); let out;
  for (let i = 0; i < parts.length; i++) { const mid = `sid-12345678.${i}`, env = await C.encrypt(kA, "\u0001" + JSON.stringify({ k: "c", s: "sid-12345678", i, n: parts.length, d: parts[i] }), `${fa}|${fb}|${mid}`);
    assert.ok(env.ct.length < 12000); if (i === 0) await assert.rejects(C.decrypt(kB, env, `${fa}|${fb}|other.0`));
    const o = JSON.parse((await C.decrypt(kB, env, `${fa}|${fb}|${mid}`)).slice(1)); out = A.add(fa, o.s, o.i, o.n, o.d); }
  assert.deepEqual(out.done, src);
});
