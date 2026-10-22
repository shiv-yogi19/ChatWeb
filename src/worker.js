import { checkProof } from "../public/js/crypto.js";
// SENDORA relay: validates, routes ciphertext, tracks presence. Never sees plaintext.
const REACT = ["❤️", "😂", "🔥", "👍", "😮", "😢", "🎉"];
const J = JSON.stringify;
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
export async function fpOf(j) {
  return hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(j.x + "." + j.y))).slice(0, 32);
}
export function cleanName(n) {
  if (typeof n !== "string") return null;
  n = n.trim();
  return n && n.length <= 24 && !/[\u0000-\u001f<>]/.test(n) && !/^(system|admin|sendora)/i.test(n) ? n : null;
}
const okPub = (p) => p && p.kty === "EC" && p.crv === "P-256" && typeof p.x === "string" && typeof p.y === "string" && p.x.length < 60 && p.y.length < 60;
const str = (s, max) => typeof s === "string" && s.length > 0 && s.length <= max;

export default {
  fetch(req, env) {
    const u = new URL(req.url);
    if (u.pathname !== "/ws") return new Response("Not found", { status: 404 });
    if (req.headers.get("Upgrade") !== "websocket") return new Response("Expected WebSocket", { status: 426 });
    const o = req.headers.get("Origin");
    let oh = null; try { oh = o && new URL(o).host; } catch {}
    if (oh !== u.host) return new Response("Forbidden origin", { status: 403 });
    return env.HUB.get(env.HUB.idFromName("global")).fetch(req);
  },
};

export class Hub {
  constructor(state) {
    this.s = state;
    this.rl = new WeakMap();
    this.routed = new Set(); // "sender|recipient|mid" for ack/reaction authorization
    state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }
  async fetch() {
    if (this.s.getWebSockets().length >= 200) return new Response("Server full", { status: 503 });
    const p = new WebSocketPair();
    this.s.acceptWebSocket(p[1]);
    await this.challenge(p[1]);
    return new Response(null, { status: 101, webSocket: p[0] });
  }
  // Proof-of-possession: per-connection ephemeral ECDH key + nonce; client must return HMAC(ECDH(clientPriv, serverPub), nonce). Single use, 15 s.
  async challenge(ws) {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const n = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const sp = await crypto.subtle.exportKey("jwk", kp.publicKey), spriv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    ws.serializeAttachment({ pend: { n, spriv, exp: Date.now() + 15000 } });
    ws.send(J({ t: "challenge", n, spub: { kty: "EC", crv: "P-256", x: sp.x, y: sp.y } }));
  }
  live(ex) {
    return this.s.getWebSockets().filter((w) => w !== ex).map((w) => [w, w.deserializeAttachment()]).filter((x) => x[1]?.id);
  }
  push(ex) {
    const m = J({ t: "presence", users: this.live(ex).map((x) => x[1]) });
    for (const [w] of this.live(ex)) try { w.send(m); } catch {}
  }
  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string" || raw.length > 16384) return ws.close(1009, "too large");
    const now = Date.now();
    let r = this.rl.get(ws) || { n: 0, t: now };
    if (now - r.t > 10000) r = { n: 0, t: now };
    this.rl.set(ws, r);
    if (++r.n > 40) return ws.send(J({ t: "err", code: "rate" }));
    let m;
    try { m = JSON.parse(raw); } catch { return ws.send(J({ t: "err", code: "json" })); }
    if (!m || typeof m !== "object") return ws.send(J({ t: "err", code: "shape" }));
    const me = ws.deserializeAttachment();
    if (m.t === "hello") {
      if (me?.id) return ws.send(J({ t: "err", code: "hello" }));
      const pend = me?.pend; ws.serializeAttachment({}); // challenge is single-use
      const name = cleanName(m.name);
      const ok = pend && Date.now() <= pend.exp && name && okPub(m.pub) && typeof m.proof === "string" && m.proof.length < 200 &&
        (await checkProof(pend.spriv, m.pub, pend.n, m.proof).catch(() => false));
      if (!ok) { ws.send(J({ t: "err", code: "auth" })); return ws.close(4003, "auth failed"); }
      const id = await fpOf(m.pub);
      for (const [w, a] of this.live(ws)) if (a.id === id) w.close(4000, "replaced");
      ws.serializeAttachment({ id, name, pub: { kty: "EC", crv: "P-256", x: m.pub.x, y: m.pub.y } });
      ws.send(J({ t: "welcome", id }));
      return this.push();
    }
    if (!me?.id) return ws.send(J({ t: "err", code: "auth" }));
    if (m.t === "rename") {
      const name = cleanName(m.name);
      if (!name) return ws.send(J({ t: "err", code: "name" }));
      ws.serializeAttachment({ ...me, name });
      return this.push();
    }
    const mid = m.mid;
    if (!["msg", "ack", "typing", "react"].includes(m.t) || !str(m.to, 64) || (m.t !== "typing" && !str(mid, 40)))
      return ws.send(J({ t: "err", code: "invalid", mid }));
    const k = (a, b) => `${a}|${b}|${mid}`;
    if (m.t === "msg" && this.routed.has(k(me.id, m.to))) return ws.send(J({ t: "err", code: "dup", mid }));
    if (m.t === "ack" && !this.routed.has(k(m.to, me.id))) return ws.send(J({ t: "err", code: "invalid", mid }));
    if (m.t === "react" && !this.routed.has(k(m.to, me.id)) && !this.routed.has(k(me.id, m.to))) return ws.send(J({ t: "err", code: "invalid", mid }));
    const target = m.to === me.id ? null : this.live(ws).find((x) => x[1].id === m.to)?.[0];
    if (!target) return m.t === "msg" ? ws.send(J({ t: "err", code: "offline", mid })) : undefined;
    let out;
    if (m.t === "msg") {
      const e = m.env;
      if (!e || e.v !== 1 || !str(e.iv, 32) || !str(e.ct, 12000)) return ws.send(J({ t: "err", code: "envelope", mid }));
      out = { t: "msg", from: me.id, mid, env: { v: 1, iv: e.iv, ct: e.ct } };
    } else if (m.t === "ack") {
      if (m.k !== "delivered" && m.k !== "read") return ws.send(J({ t: "err", code: "invalid" }));
      out = { t: "ack", from: me.id, mid, k: m.k };
    } else if (m.t === "typing") out = { t: "typing", from: me.id, on: m.on === true };
    else {
      if (m.e !== null && !REACT.includes(m.e)) return ws.send(J({ t: "err", code: "reaction" }));
      out = { t: "react", from: me.id, mid, e: m.e };
    }
    target.send(J(out));
    if (m.t === "msg") { if (this.routed.size > 5000) this.routed.clear(); this.routed.add(k(me.id, m.to)); }
    if (m.t === "msg") ws.send(J({ t: "sent", mid })); // accepted for a live recipient; NOT delivery
  }
  webSocketClose(ws) { try { ws.close(); } catch {} this.push(ws); }
  webSocketError(ws) { this.push(ws); }
}
