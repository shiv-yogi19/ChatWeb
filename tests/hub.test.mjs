import test from "node:test";
import assert from "node:assert/strict";
globalThis.WebSocketRequestResponsePair = class {};
const { Hub } = await import("../src/worker.js");
import * as C from "../public/js/crypto.js";
const env = () => { const socks = []; return { socks, hub: new Hub({ setWebSocketAutoResponse() {}, acceptWebSocket() {}, getWebSockets: () => socks.filter((s) => !s.closed) }) }; };
const sock = () => ({ out: [], att: null, closed: null, send(x) { this.out.push(JSON.parse(x)); }, close(c) { this.closed = c ?? 1000; }, serializeAttachment(a) { this.att = a; }, deserializeAttachment() { return this.att; } });
async function conn(E, name, ident, signWith) {
  const ws = sock(); E.socks.push(ws); await E.hub.challenge(ws); const ch = ws.out.shift();
  ident ||= await C.genKey(); const proof = await C.prove((signWith || ident).priv, ch.spub, ch.n);
  const hello = JSON.stringify({ t: "hello", name, pub: ident.pub, proof }); await E.hub.webSocketMessage(ws, hello);
  return { ws, ident, id: await C.fingerprint(ident.pub), hello };
}
const tx = (E, c, o) => E.hub.webSocketMessage(c.ws, JSON.stringify(o));
const last = (c) => c.ws.out.at(-1);
test("valid auth, presence, duplicate session replaces older", async () => {
  const E = env(), a = await conn(E, "A"), b = await conn(E, "B");
  assert.equal(a.ws.out.find((m) => m.t === "welcome").id, a.id);
  assert.ok(last(a).users.some((u) => u.id === b.id));
  const a2 = await conn(E, "A2", a.ident); assert.equal(a.ws.closed, 4000); assert.ok(a2.ws.att.id);
});
test("spoofing, replay, expiry, hello-after-auth rejected", async () => {
  const E = env(), v = await conn(E, "V"), evil = await C.genKey();
  const s = await conn(E, "Evil", v.ident, evil); assert.equal(s.ws.closed, 4003); assert.ok(!E.hub.live().some((x) => x[1].name === "Evil"));
  const r = sock(); E.socks.push(r); await E.hub.challenge(r); await E.hub.webSocketMessage(r, v.hello); assert.equal(r.closed, 4003);
  const real = Date.now; const q = sock(); E.socks.push(q); await E.hub.challenge(q); const ch = q.out.shift(); const k = await C.genKey();
  const proof = await C.prove(k.priv, ch.spub, ch.n); Date.now = () => real() + 20000;
  await E.hub.webSocketMessage(q, JSON.stringify({ t: "hello", name: "Late", pub: k.pub, proof })); Date.now = real; assert.equal(q.closed, 4003);
  await tx(E, v, { t: "hello", name: "X", pub: v.ident.pub, proof: "x" }); assert.equal(v.ws.closed, null); assert.ok(v.ws.att.id);
});
test("routing, ciphertext only, ack forgery, dup, reactions, receipts", async () => {
  const E = env(), a = await conn(E, "A"), b = await conn(E, "B"), c = await conn(E, "C");
  const kA = await C.deriveKey(a.ident.priv, b.ident.pub, a.id), kB = await C.deriveKey(b.ident.priv, a.ident.pub, b.id);
  const env1 = await C.encrypt(kA, "secret-plain", `${a.id}|${b.id}|m1`);
  await tx(E, a, { t: "msg", to: b.id, mid: "m1", env: env1 });
  const got = b.ws.out.find((m) => m.t === "msg"); assert.equal(got.from, a.id);
  assert.equal(await C.decrypt(kB, got.env, `${a.id}|${b.id}|m1`), "secret-plain");
  assert.ok(!JSON.stringify([a, b, c].map((x) => x.ws.out)).includes("secret-plain"));
  assert.ok(!c.ws.out.some((m) => m.t === "msg")); assert.equal(last(a).t, "sent");
  await tx(E, c, { t: "ack", to: a.id, mid: "m1", k: "read" }); assert.equal(last(c).code, "invalid"); assert.ok(!a.ws.out.some((m) => m.t === "ack"));
  await tx(E, b, { t: "ack", to: a.id, mid: "m1", k: "delivered" }); await tx(E, b, { t: "ack", to: a.id, mid: "m1", k: "bogus" });
  assert.equal(a.ws.out.filter((m) => m.t === "ack").length, 1); assert.equal(last(b).code, "invalid");
  await tx(E, a, { t: "msg", to: b.id, mid: "m1", env: env1 }); assert.equal(last(a).code, "dup");
  await tx(E, b, { t: "react", to: a.id, mid: "m1", e: "🔥" }); assert.equal(last(a).e, "🔥");
  await tx(E, b, { t: "react", to: a.id, mid: "m1", e: "<img>" }); assert.equal(last(b).code, "reaction");
  await tx(E, c, { t: "react", to: a.id, mid: "m1", e: "👍" }); assert.equal(last(c).code, "invalid");
  await tx(E, a, { t: "typing", to: b.id, on: true }); assert.equal(last(b).on, true);
});
test("offline, invalid, oversize, rate limit, presence cleanup", async () => {
  const E = env(), a = await conn(E, "A"), b = await conn(E, "B");
  await tx(E, a, { t: "msg", to: "f".repeat(32), mid: "z", env: { v: 1, iv: "a", ct: "b" } }); assert.equal(last(a).code, "offline");
  await tx(E, a, { t: "nope", to: b.id, mid: "q" }); assert.equal(last(a).code, "invalid");
  await tx(E, a, { t: "msg", to: b.id, mid: "q", env: { v: 1, iv: "a", ct: "x".repeat(13000) } }); assert.equal(last(a).code, "envelope");
  await E.hub.webSocketMessage(a.ws, "{bad"); assert.equal(last(a).code, "json");
  for (let i = 0; i < 45; i++) await tx(E, a, { t: "typing", to: b.id, on: true }); assert.equal(last(a).code, "rate");
  await E.hub.webSocketMessage(b.ws, "y".repeat(20000)); assert.equal(b.ws.closed, 1009);
  E.hub.webSocketClose(a.ws); assert.ok(!last(b).users?.some((u) => u.id === a.id));
});
test("origin policy: missing or foreign Origin rejected", async () => {
  const { default: W } = await import("../src/worker.js"), h = (o) => new Request("https://x.test/ws", { headers: { Upgrade: "websocket", ...(o ? { Origin: o } : {}) } });
  assert.equal((await W.fetch(h(null), {})).status, 403); assert.equal((await W.fetch(h("https://evil.test"), {})).status, 403);
});
