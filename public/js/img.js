// Image chunk helpers (pure, testable). Images are re-encoded to JPEG client-side, then sent as encrypted chunks.
export const MAX_BYTES = 150000, CHUNK = 6000, MAX_CHUNKS = Math.ceil(MAX_BYTES / CHUNK);
export const b64 = (u) => btoa(String.fromCharCode(...u));
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export const split = (bytes) => { const o = []; for (let i = 0; i < bytes.length; i += CHUNK) o.push(b64(bytes.subarray(i, i + CHUNK))); return o; };
export const isJpeg = (b) => b.length > 4 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
export class Assembler {
  constructor(maxTransfers = 20, ttl = 60000, now = () => Date.now()) { this.m = new Map(); this.max = maxTransfers; this.ttl = ttl; this.now = now; }
  sweep() { for (const [k, e] of this.m) if (this.now() - e.t > this.ttl) this.m.delete(k); }
  cancel(from, sid) { this.m.delete(from + ":" + sid); }
  dropPeer(from) { for (const k of this.m.keys()) if (k.startsWith(from + ":")) this.m.delete(k); }
  add(from, sid, i, n, d) {
    this.sweep();
    if (typeof sid !== "string" || !/^[\w-]{8,36}$/.test(sid) || !Number.isInteger(n) || n < 1 || n > MAX_CHUNKS || !Number.isInteger(i) || i < 0 || i >= n || typeof d !== "string" || d.length > 8200) return { error: "invalid chunk" };
    const key = from + ":" + sid; let e = this.m.get(key);
    if (!e) { if (this.m.size >= this.max) return { error: "too many transfers" }; e = { n, parts: new Map(), t: this.now() }; this.m.set(key, e); }
    if (e.n !== n) { this.m.delete(key); return { error: "inconsistent chunk count" }; }
    if (e.parts.has(i)) return { dup: true };
    let raw; try { raw = unb64(d); } catch { this.m.delete(key); return { error: "bad encoding" }; }
    if (raw.length > CHUNK) { this.m.delete(key); return { error: "chunk too large" }; }
    e.parts.set(i, raw); if (e.parts.size < n) return { ok: true };
    this.m.delete(key); const out = new Uint8Array([...e.parts.values()].reduce((a, p) => a + p.length, 0)); let o = 0;
    for (let j = 0; j < n; j++) { out.set(e.parts.get(j), o); o += e.parts.get(j).length; }
    return out.length > MAX_BYTES || !isJpeg(out) ? { error: "invalid image" } : { done: out };
  }
}
