import * as C from "./crypto.js";
import * as I from "./img.js";
const $ = (s) => document.querySelector(s), LS = localStorage;
const R = ["❤️", "😂", "🔥", "👍", "😮", "😢", "🎉"];
const TAG = ["Every Message Has a Story.", "Send Beyond Words.", "Your Words. Your Connection.", "A New Way to Say Hello.", "Decode the Distance.", "Where Every Signal Connects.", "More Than Just a Message."];
const LBL = { sending: "Sending…", sent: "✓ Sent", delivered: "✓✓ Delivered", read: "✓✓ Read", failed: "⚠ Failed — tap to retry" };
const RANK = { failed: -1, sending: 0, sent: 1, delivered: 2, read: 3 };
const jg = (k, d) => { try { return JSON.parse(LS[k]) ?? d; } catch { return d; } }, js = (k, v) => (LS[k] = JSON.stringify(v));
const S = { asm: new I.Assembler(), names: jg("sdr_names", {}), pend: null, name: LS.sdr_name || "", ident: jg("sdr_ident", null), me: "", peers: new Map(), chats: new Map(), keys: new Map(), seen: new Set(), unread: new Map(), drafts: new Map(), open: null, ws: null, tries: 0, q: "", ty: null,
  blocked: jg("sdr_blocked", []), ver: jg("sdr_ver", []), prefs: { theme: "dark", rr: true, rm: false, sound: true, vib: true, notif: false, muted: [], ...jg("sdr_prefs", {}) } };
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x != null) e.textContent = x; return e; };
const toast = (m) => { const t = $("#toast"); t.textContent = m; t.classList.add("on"); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("on"), 3500); };
const badName = (n) => !n || n.length > 24 || /[\u0000-\u001f<>]/.test(n) || /^(system|admin|sendora)/i.test(n);
const chat = (id) => S.chats.get(id) || (S.chats.set(id, []), S.chats.get(id));
const base = (mid) => mid.split(".")[0], wm = (m) => (m.kind === "img" ? m.mid + ".0" : m.mid);
const aad = (a, b, mid) => `${a}|${b}|${mid}`;
const fmt = (s) => s.match(/.{1,4}/g).join("-");
const rmOn = () => S.prefs.rm || matchMedia("(prefers-reduced-motion: reduce)").matches;
function applyPrefs() { document.documentElement.dataset.theme = S.prefs.theme; document.documentElement.classList.toggle("rm", S.prefs.rm); js("sdr_prefs", S.prefs); }

function intro() {
  let i; do i = Math.floor(Math.random() * TAG.length); while (TAG[i] === sessionStorage.tag);
  sessionStorage.tag = TAG[i]; $("#tag").textContent = TAG[i];
  let done = false;
  const go = () => { if (done) return; done = true; $("#intro").classList.add("out");
    setTimeout(() => { $("#intro").hidden = true; S.name && S.ident ? boot() : ($("#entry").hidden = false, $("#nm").focus()); }, rmOn() ? 0 : 350); };
  $("#intro").onclick = go; setTimeout(go, rmOn() ? 300 : 1800);
}
$("#rnd").onclick = () => ($("#nm").value = ["Redmi", "Galaxy", "Pixel", "Android", "Device"][Math.floor(Math.random() * 5)] + "_" + (1 + Math.floor(Math.random() * 99)));
$("#cont").onclick = () => { const n = $("#nm").value.trim();
  if (badName(n)) return ($("#nerr").textContent = "Use 1–24 characters, no < > or control characters, and don't start with System, Admin or Sendora.");
  S.name = n; LS.sdr_name = n; $("#entry").hidden = true; boot(); };
$("#nm").onkeydown = (e) => e.key === "Enter" && $("#cont").click();

async function boot() {
  if (!S.ident) { S.ident = await C.genKey(); js("sdr_ident", S.ident); }
  S.me = await C.fingerprint(S.ident.pub); await loadHistory();
  $("#app").hidden = false; $("#me").textContent = S.name.slice(0, 2).toUpperCase(); connect(); render();
}
const status = (t) => ($("#conn").textContent = t);
const send = (o) => (S.ws?.readyState === 1 ? (S.ws.send(JSON.stringify(o)), true) : false);
function connect() {
  clearTimeout(S.rt);
  const ws = (S.ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws"));
  status("Connecting…");
  ws.onopen = () => { S.tries = 0; S.hb = setInterval(() => ws.readyState === 1 && ws.send("ping"), 25000); status("● Connected"); };
  ws.onmessage = (e) => { if (e.data === "pong") return; try { onMsg(JSON.parse(e.data)); } catch (err) { console.warn("bad frame"); } };
  ws.onclose = (e) => { clearInterval(S.hb); S.peers.clear(); render();
    if (e.code === 4000) return status("Opened in another tab"); if (e.code === 4003) toast("Authentication failed; retrying.");
    status("○ Reconnecting…"); S.rt = setTimeout(connect, Math.min(30000, 1000 * 2 ** S.tries++) * (0.5 + Math.random() / 2)); };
}
addEventListener("online", () => S.ws?.readyState > 1 && S.tries++ >= 0 && connect());
addEventListener("offline", () => status("○ Offline"));

const key = (id) => S.keys.get(id) || (S.keys.set(id, C.deriveKey(S.ident.priv, S.peers.get(id).pub, S.me)), S.keys.get(id));
const findMsg = (mid, id) => (id ? [id] : [...S.chats.keys()]).map((k) => chat(k).find((m) => m.mid === mid)).find(Boolean);
function setState(m, k) { if (m && m.mine && RANK[k] > RANK[m.state]) m.state = k; }
async function onMsg(m) {
  if (m.from && S.blocked.includes(m.from)) return;
  switch (m.t) {
    case "challenge": send({ t: "hello", name: S.name, pub: S.ident.pub, proof: await C.prove(S.ident.priv, m.spub, m.n) }); return;
    case "presence": {
      const ok = [];
      for (const u of m.users) if (u.id !== S.me && (await C.fingerprint(u.pub)) === u.id) ok.push([u.id, u]); // never trust server-asserted ids
      S.peers = new Map(ok); for (const [id, u] of ok) S.names[id] = u.name; js("sdr_names", S.names); render(); break; }
    case "msg": return incoming(m);
    case "sent": { const x = findMsg(base(m.mid)); if (x && (x.kind !== "img" || m.mid === x.mid + "." + (x.n - 1))) setState(x, "sent"); break; }
    case "err": { const x = findMsg(m.mid && base(m.mid)); if (x && x.mine && x.state === "sending") x.state = "failed";
      toast(m.code === "offline" ? "Recipient is offline. SENDORA doesn't queue messages — retry when they're back." : m.code === "rate" ? "Slow down — too many messages." : "Message rejected."); break; }
    case "ack": { const x = findMsg(base(m.mid), m.from); if (x?.kind === "img" && m.k === "delivered") { x.acked = (x.acked || 0) + 1; if (x.acked >= x.n) setState(x, "delivered"); } else setState(x, m.k); break; }
    case "typing": if (m.from === S.open) { $("#typing").hidden = !m.on; clearTimeout(S.tc); if (m.on) S.tc = setTimeout(() => ($("#typing").hidden = true), 4000); } return;
    case "react": { const x = findMsg(base(m.mid), m.from); if (x && (m.e === null || R.includes(m.e))) x.rx[m.from] = m.e; break; }
  }
  render();
}
async function incoming(m) {
  const k = m.from + ":" + m.mid; if (S.seen.has(k) || !S.peers.has(m.from)) return; S.seen.add(k);
  let text = null; try { text = await C.decrypt(await key(m.from), m.env, aad(m.from, S.me, m.mid)); } catch {}
  if (text !== null) send({ t: "ack", to: m.from, mid: m.mid, k: "delivered" });
  let msg = { mid: m.mid, mine: false, text: text ?? "⚠ Could not decrypt this message", bad: text === null, ts: Date.now(), rx: {} };
  if (text && text[0] === "\u0001") { msg = await special(m.from, text, m.mid); if (!msg) return; }
  chat(m.from).push(msg);
  if (S.open === m.from && document.visibilityState === "visible") readAll(m.from); else { S.unread.set(m.from, (S.unread.get(m.from) || 0) + 1); notify(m.from); }
  render();
}
async function special(from, text, mid) {
  let o; try { o = JSON.parse(text.slice(1)); } catch { return null; }
  if (o?.k === "loc") return typeof o.lat === "number" && typeof o.lon === "number" && Math.abs(o.lat) <= 90 && Math.abs(o.lon) <= 180 ? { mid, kind: "loc", lat: o.lat, lon: o.lon, mine: false, text: "📍 Shared location", ts: Date.now(), rx: {} } : null;
  if (o?.k !== "c") return null;
  const r = S.asm.add(from, o.s, o.i, o.n, o.d); if (!r.done) { if (r.error) toast("Image transfer failed: " + r.error); return null; }
  if (chat(from).some((x) => x.mid === o.s)) return null;
  const blob = new Blob([r.done], { type: "image/jpeg" });
  try { (await createImageBitmap(blob)).close?.(); } catch { return { mid: o.s, mine: false, text: "⚠ Received an invalid image", bad: true, ts: Date.now(), rx: {} }; }
  return { mid: o.s, kind: "img", blob, url: URL.createObjectURL(blob), mine: false, text: "[image]", ts: Date.now(), rx: {} };
}
function notify(id) { const p = S.prefs; if (p.muted.includes(id)) return; toast("New message from " + (S.peers.get(id)?.name || S.names[id] || "someone"));
  if (p.vib && navigator.vibrate) navigator.vibrate(50);
  if (p.sound) try { const a = new (window.AudioContext || webkitAudioContext)(), o = a.createOscillator(), g = a.createGain(); o.connect(g); g.connect(a.destination); g.gain.value = 0.05; o.frequency.value = 660; o.start(); o.stop(a.currentTime + 0.12); setTimeout(() => a.close(), 300); } catch {}
  if (p.notif && document.visibilityState === "hidden" && window.Notification?.permission === "granted") new Notification("SENDORA", { body: "New message", tag: "sendora-" + id }); }
function readAll(id) { for (const m of chat(id)) if (!m.mine && !m.read) { m.read = true; if (S.prefs.rr && !m.bad) send({ t: "ack", to: id, mid: wm(m), k: "read" }); } S.unread.delete(id); }

function render() { renderList(); renderChat(); persist(); }
function renderList() {
  const u = $("#users"); u.replaceChildren(); const q = S.q.toLowerCase(), hit = (id, n) => !S.blocked.includes(id) && (!q || (n || "").toLowerCase().includes(q) || id.includes(q));
  const L = [...S.peers.values()].filter((p) => hit(p.id, p.name)), off = [...S.chats.keys()].filter((id) => !S.peers.has(id) && S.chats.get(id).length && hit(id, S.names[id]));
  if (!L.length && !off.length) return u.append(el("div", "empty", q ? "No users match your search." : "No one else is online right now. Open SENDORA on another device or browser to start a chat."));
  const row = (id, name, on) => { const b = el("button", "user" + (S.open === id ? " sel" : "")); b.append(el("span", "av", (name || "?").slice(0, 2).toUpperCase()), el("span", "nm", (name || "Offline user") + " · " + id.slice(0, 4)), el("span", on ? "on" : "off", on ? "● Online" : "○ Offline")); const n = S.unread.get(id); if (n) b.append(el("span", "bd", n)); b.onclick = () => openChat(id); u.append(b); };
  for (const p of L) row(p.id, p.name, true); for (const id of off) row(id, S.names[id], false);
}
function renderChat() {
  const id = S.open, p = S.peers.get(id), box = $("#msgs"); $("#app").classList.toggle("chatting", !!id); $("#composer").hidden = !id; $("#mu").textContent = S.prefs.muted.includes(id) ? "🔕" : "🔔";
  if (!id) { $("#cn").textContent = "SENDORA"; $("#cv").textContent = ""; return box.replaceChildren(el("div", "empty", "Select someone online to start an end-to-end encrypted chat.")); }
  $("#cn").textContent = p ? p.name : S.names[id] || "Offline user"; $("#cv").textContent = (p ? "Online" : "Offline — can't send") + " · " + (S.ver.includes(id) ? "Verified" : "Unverified");
  const near = box.scrollHeight - box.scrollTop - box.clientHeight < 80; box.replaceChildren();
  for (const m of chat(id)) {
    const w = el("div", "b " + (m.mine ? "me" : "them")); w.tabIndex = 0; if (m.kind === "img" && m.url) { const im = el("img", "pic"); im.src = m.url; im.alt = "Shared image"; w.append(im); } else w.append(el("div", "", m.text));
    if (m.kind === "loc") { const a = el("a", "", "Open in OpenStreetMap"); a.href = `https://www.openstreetmap.org/?mlat=${m.lat}&mlon=${m.lon}#map=15/${m.lat}/${m.lon}`; a.target = "_blank"; a.rel = "noopener noreferrer"; w.append(a, el("div", "", m.lat.toFixed(5) + ", " + m.lon.toFixed(5))); }
    const meta = el("small", "meta", new Date(m.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + (m.mine ? " · " + LBL[m.state] + (m.prog ? " " + m.prog : "") : ""));
    if (m.state === "failed") { meta.tabIndex = 0; meta.setAttribute("role", "button"); meta.onclick = () => retry(id, m); } w.append(meta);
    const c = {}; for (const e of Object.values(m.rx)) if (e) c[e] = (c[e] || 0) + 1;
    if (Object.keys(c).length) w.append(el("div", "rx", Object.entries(c).map(([e, n]) => e + (n > 1 ? n : "")).join(" ")));
    w.oncontextmenu = (e) => { e.preventDefault(); panel(e.clientX, e.clientY, id, m); };
    w.onkeydown = (e) => { if (e.key === "Enter") { const r = w.getBoundingClientRect(); panel(r.left + 40, r.top, id, m); } };
    let t; w.ontouchstart = (e) => { const x = e.touches[0]; t = setTimeout(() => panel(x.clientX, x.clientY, id, m), 450); }; w.ontouchend = w.ontouchmove = () => clearTimeout(t);
    box.append(w);
  }
  if (near) box.scrollTop = box.scrollHeight;
}
function panel(x, y, id, m) {
  const rp = $("#rp"); rp.replaceChildren();
  for (const r of R) { const b = el("button", "", r); b.setAttribute("role", "menuitem"); b.setAttribute("aria-label", "React " + r);
    b.onclick = () => { const cur = m.rx.me === r ? null : r; m.rx.me = cur; send({ t: "react", to: id, mid: wm(m), e: cur }); rp.hidden = true; render(); }; rp.append(b); }
  rp.hidden = false; rp.style.left = Math.max(8, Math.min(x - rp.offsetWidth / 2, innerWidth - rp.offsetWidth - 8)) + "px"; rp.style.top = Math.max(8, Math.min(y - 56, innerHeight - 64)) + "px"; rp.firstChild.focus();
}
addEventListener("pointerdown", (e) => { if (!$("#rp").contains(e.target)) $("#rp").hidden = true; });
addEventListener("keydown", (e) => e.key === "Escape" && ($("#rp").hidden = true));

function openChat(id) {
  if (S.open) typingOff(); else history.pushState({ c: 1 }, ""); S.open = id; $("#in").value = S.drafts.get(id) || ""; $("#typing").hidden = true; readAll(id); render();
}
function closeChat() { typingOff(); if (S.open) S.drafts.set(S.open, $("#in").value); S.open = null; $("#rp").hidden = true; $("#typing").hidden = true; $("#pv").hidden = true; S.pend = null; render(); }
$("#back").onclick = () => history.back();
addEventListener("popstate", () => S.open && closeChat());
function typingOff() { clearTimeout(S.tt); if (S.ty) { send({ t: "typing", to: S.ty, on: false }); S.ty = null; } }
$("#in").oninput = (e) => { e.target.style.height = "auto"; e.target.style.height = e.target.scrollHeight + "px";
  if (!S.ty && S.open) { send({ t: "typing", to: S.open, on: true }); S.ty = S.open; } clearTimeout(S.tt); S.tt = setTimeout(typingOff, 2500); };
$("#in").onkeydown = (e) => { if (e.key === "Enter" && !e.shiftKey && !matchMedia("(pointer:coarse)").matches) { e.preventDefault(); sendText(); } };
$("#send").onclick = sendText;
async function transmit(id, m) {
  m.state = "sending"; render();
  try { const env = await C.encrypt(await key(id), m.wire ?? m.text, aad(S.me, id, m.mid));
    if (!send({ t: "msg", to: id, mid: m.mid, env })) m.state = "failed"; } catch { m.state = "failed"; }
  setTimeout(() => { if (m.state === "sending") { m.state = "failed"; render(); } }, 8000); render();
}
function sendText() {
  const id = S.open, text = $("#in").value.replace(/\u0001/g, "").trim(); if (!id || !text) return;
  if (!S.peers.has(id)) return toast("They're offline. SENDORA doesn't queue messages.");
  const m = { mid: crypto.randomUUID(), mine: true, text, ts: Date.now(), rx: {}, state: "sending" };
  chat(id).push(m); $("#in").value = ""; $("#in").style.height = "auto"; S.drafts.delete(id); typingOff(); transmit(id, m);
}
const retry = (id, m) => !S.peers.has(id) ? toast("Recipient is offline.") : m.kind === "img" ? (m.mid = crypto.randomUUID(), transmitImg(id, m)) : transmit(id, m);

$("#sbtn").onclick = () => { const q = $("#q"); q.hidden = !q.hidden; if (q.hidden) { q.value = ""; S.q = ""; render(); } else q.focus(); };
let qt; $("#q").oninput = (e) => { clearTimeout(qt); qt = setTimeout(() => { S.q = e.target.value.trim(); renderList(); }, 200); };
$("#vf").onclick = () => { const p = S.peers.get(S.open); if (!p) return; const sn = C.safetyNumber(S.me, p.id);
  if (S.ver.includes(p.id)) { if (confirm("Remove verification for " + p.name + "?")) { S.ver = S.ver.filter((x) => x !== p.id); js("sdr_ver", S.ver); render(); } return; }
  const v = prompt(`Safety number with ${p.name}:
${sn}

Ask ${p.name} to read the number on THEIR device (in person or by call), then type it here. A name alone proves nothing.`);
  if (v === null) return;
  if (C.numbersMatch(v, sn)) { S.ver.push(p.id); js("sdr_ver", S.ver); toast("Verified."); } else toast("Numbers differ. NOT verified — typo or possible interception."); render(); };
$("#bl").onclick = () => { const id = S.open; if (id && confirm("Block this identity? They'll be hidden and their messages ignored on this device. They can still reach you by creating a new identity.")) { S.blocked.push(id); js("sdr_blocked", S.blocked); S.chats.delete(id); history.back(); } };
$("#pr").onclick = () => { const p = S.peers.get(S.open); $("#phead").replaceChildren(el("h1", "", "SENDORA"), el("div", "", "Created By Shiv Yogi"),
  el("div", "", `Conversation: ${S.name} and ${p ? p.name : "(offline user)"} — printed ${new Date().toLocaleString()}`), el("small", "", "This printout is a copy outside the encrypted conversation."));
  print(); };

function fill() { $("#th").value = S.prefs.theme; $("#rr").checked = S.prefs.rr; $("#rm").checked = S.prefs.rm; $("#sn").value = S.name; $("#idn").textContent = fmt(S.me);
  $("#snd").checked = S.prefs.sound; $("#vib").checked = S.prefs.vib; $("#nt").checked = S.prefs.notif;
  $("#tr").textContent = "Translation: " + ("Translator" in self ? "this browser has an on-device Translator API, but SENDORA does not use it yet." : "unavailable in this browser.");
  $("#cs").textContent = "Connection: " + $("#conn").textContent; const bk = $("#bk"); bk.replaceChildren();
  if (!S.blocked.length) bk.append(el("small", "", "No blocked identities."));
  for (const id of S.blocked) { const b = el("button", "", "Unblock " + id.slice(0, 8)); b.onclick = () => { S.blocked = S.blocked.filter((x) => x !== id); js("sdr_blocked", S.blocked); fill(); render(); }; bk.append(b); } }
$("#me").onclick = () => { fill(); $("#set").showModal(); }; $("#cl").onclick = () => $("#set").close();
$("#th").onchange = (e) => { S.prefs.theme = e.target.value; applyPrefs(); };
$("#rr").onchange = (e) => { S.prefs.rr = e.target.checked; applyPrefs(); };
$("#rm").onchange = (e) => { S.prefs.rm = e.target.checked; applyPrefs(); };
$("#svn").onclick = () => { const n = $("#sn").value.trim(); if (badName(n)) return toast("Invalid name."); S.name = n; LS.sdr_name = n; $("#me").textContent = n.slice(0, 2).toUpperCase(); send({ t: "rename", name: n }); toast("Name saved."); };
$("#cp").onclick = async () => { try { await navigator.clipboard.writeText(S.me); toast("Copied."); } catch { toast("Clipboard unavailable — select the number and copy manually."); } };
$("#dl").onclick = async () => { if (confirm("Delete ALL chat history stored on this device (including images)? The other person's copy and printed copies are not affected.")) { await delChat(null); render(); toast("All local chats deleted."); } };
$("#ci").onclick = async () => { if (confirm("Clear your identity? Your private key is destroyed and cannot be recovered. You'll get a new identity and lose verified and blocked lists.")) { await delChat(null); ["sdr_names", "sdr_ident", "sdr_name", "sdr_blocked", "sdr_ver"].forEach((k) => LS.removeItem(k)); location.reload(); } };
$("#snd").onchange = (e) => { S.prefs.sound = e.target.checked; applyPrefs(); };
$("#vib").onchange = (e) => { S.prefs.vib = e.target.checked; applyPrefs(); };
$("#nt").onchange = async (e) => { if (!e.target.checked) { S.prefs.notif = false; return applyPrefs(); }
  if (!("Notification" in window)) { e.target.checked = false; return toast("Notifications aren't supported in this browser."); }
  const r = await Notification.requestPermission(); S.prefs.notif = r === "granted"; e.target.checked = S.prefs.notif; if (r !== "granted") toast("Permission not granted. Change it in your browser's site settings."); applyPrefs(); };
$("#mu").onclick = () => { const id = S.open, i = S.prefs.muted.indexOf(id); i < 0 ? S.prefs.muted.push(id) : S.prefs.muted.splice(i, 1); applyPrefs(); render(); };
$("#dc").onclick = async () => { const id = S.open; if (id && confirm("Delete this conversation from this device? The other person's copy is not affected.")) { await delChat(id); history.back(); } };
const MIMES = ["image/jpeg", "image/png", "image/webp"];
$("#att").onclick = () => S.open && $("#file").click();
$("#file").onchange = async (e) => { const f = e.target.files[0]; e.target.value = ""; if (!f) return;
  if (!MIMES.includes(f.type) || f.size > 8e6) return toast("Choose a JPEG, PNG or WebP image under 8 MB.");
  try { const bmp = await createImageBitmap(f); if (bmp.width > 8000 || bmp.height > 8000) throw 0;
    let sc = Math.min(1, 1024 / Math.max(bmp.width, bmp.height)), blob;
    for (const q of [0.75, 0.6, 0.45, 0.3, 0.2]) { const c = document.createElement("canvas"); c.width = Math.max(1, Math.round(bmp.width * sc)); c.height = Math.max(1, Math.round(bmp.height * sc)); c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height); blob = await new Promise((r) => c.toBlob(r, "image/jpeg", q)); if (blob && blob.size <= I.MAX_BYTES) break; sc *= 0.8; }
    bmp.close?.(); if (!blob || blob.size > I.MAX_BYTES) throw 0;
    S.pend = blob; URL.revokeObjectURL($("#pvi").src); $("#pvi").src = URL.createObjectURL(blob); $("#pv").hidden = false;
  } catch { toast("This image is invalid, unsupported or too large (limit 150 KB after resizing)."); } };
$("#pvc").onclick = () => { S.pend = null; $("#pv").hidden = true; };
$("#pvs").onclick = () => { const id = S.open, blob = S.pend; $("#pv").hidden = true; S.pend = null; if (!id || !blob) return;
  if (!S.peers.has(id)) return toast("They're offline. SENDORA doesn't queue messages.");
  const m = { mid: crypto.randomUUID(), mine: true, kind: "img", blob, url: URL.createObjectURL(blob), text: "[image]", ts: Date.now(), rx: {}, state: "sending" }; chat(id).push(m); transmitImg(id, m); };
async function transmitImg(id, m) {
  m.state = "sending"; m.acked = 0; const parts = I.split(new Uint8Array(await m.blob.arrayBuffer())); m.n = parts.length;
  try { for (let i = 0; i < parts.length; i++) { if (!S.peers.has(id)) throw 0; const mid = m.mid + "." + i;
      const env = await C.encrypt(await key(id), "\u0001" + JSON.stringify({ k: "c", s: m.mid, i, n: parts.length, d: parts[i] }), aad(S.me, id, mid));
      if (!send({ t: "msg", to: id, mid, env })) throw 0; m.prog = `${i + 1}/${parts.length}`; render(); }
    setTimeout(() => { if (m.state === "sending" || m.state === "sent") { if (m.state === "sending") { m.state = "failed"; render(); } } }, 20000);
  } catch { m.state = "failed"; } m.prog = ""; render(); }
$("#loc").onclick = () => { const id = S.open, p = S.peers.get(id); if (!p) return toast("They're offline.");
  if (!navigator.geolocation) return toast("Location isn't available in this browser.");
  if (!confirm(`Share your precise current location with ${p.name}? It is end-to-end encrypted and sent once. SENDORA has no approximate mode. Your browser will ask for permission (HTTPS required).`)) return;
  navigator.geolocation.getCurrentPosition((pos) => { const lat = +pos.coords.latitude.toFixed(5), lon = +pos.coords.longitude.toFixed(5);
    const m = { mid: crypto.randomUUID(), mine: true, kind: "loc", lat, lon, text: "📍 Shared location", wire: "\u0001" + JSON.stringify({ k: "loc", lat, lon }), ts: Date.now(), rx: {}, state: "sending" }; chat(id).push(m); transmit(id, m); },
    (e) => toast(e.code === 1 ? "Location permission denied. Nothing was shared." : "Couldn't get your location."), { timeout: 10000 }); };
// Local history: IndexedDB, stored UNENCRYPTED at rest (anyone with this browser profile can read it). Keys live in localStorage, separate.
const DB = new Promise((res) => { try { const r = indexedDB.open("sendora", 1); r.onupgradeneeded = () => r.result.createObjectStore("msgs", { keyPath: "k" }); r.onsuccess = () => res(r.result); r.onerror = () => res(null); } catch { res(null); } });
const idb = async (mode, f) => { const d = await DB; if (!d) return null; return new Promise((res) => { try { const tx = d.transaction("msgs", mode), rq = f(tx.objectStore("msgs")); tx.oncomplete = () => res(rq?.result ?? true); tx.onerror = tx.onabort = () => res(null); } catch { res(null); } }); };
const sig = new Map(), sg = (m) => m.state + m.read + JSON.stringify(m.rx);
function persist() { clearTimeout(persist.t); persist.t = setTimeout(async () => { for (const [id, L] of S.chats) for (const m of L) { const k = `${S.me}|${id}|${m.mid}`; if (sig.get(k) === sg(m)) continue; sig.set(k, sg(m));
  const { url, ...r } = m; if ((await idb("readwrite", (st) => st.put({ ...r, k, owner: S.me, peer: id }))) === null) sig.delete(k); } }, 500); }
async function loadHistory() { const all = await idb("readonly", (st) => st.getAll()); if (all === null) return toast("Local history is unavailable here; chats won't survive a refresh.");
  for (const r of all.filter((x) => x.owner === S.me).sort((a, b) => a.ts - b.ts)) { const { k, owner, peer, ...m } = r; if (m.state === "sending") m.state = "failed"; if (m.blob) m.url = URL.createObjectURL(m.blob); chat(peer).push(m); sig.set(k, sg(m)); S.seen.add(peer + ":" + m.mid); } }
async function delChat(id) { const all = (await idb("readonly", (st) => st.getAll())) || [];
  for (const r of all) if (r.owner === S.me && (id === null || r.peer === id)) await idb("readwrite", (st) => st.delete(r.k));
  for (const [pid, L] of [...S.chats]) if (id === null || pid === id) { for (const m of L) m.url && URL.revokeObjectURL(m.url); S.chats.delete(pid); S.drafts.delete(pid); S.unread.delete(pid); }
  for (const k of [...sig.keys()]) if (id === null || k.split("|")[1] === id) sig.delete(k); }
applyPrefs(); intro();
