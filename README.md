# SENDORA — Created By Shiv Yogi
Anonymous global chat: Cloudflare Worker + one SQLite-backed Durable Object (WebSocket relay/presence), static frontend, browser E2EE.

## Run / deploy
    npm install
    npx wrangler dev          # local
    npx wrangler login
    npx wrangler deploy       # creates a NEW worker named "sendora"; existing workers untouched
    npm test                  # crypto tests (Node 20+)

## Crypto (see public/js/crypto.js)
ECDH P-256 -> HKDF-SHA256 (info binds both fingerprints) -> AES-256-GCM, random 96-bit nonce, AAD = sender|recipient|messageId.
Identity = SHA-256(pubkey)[0..32]; the server and clients both recompute it, so the server cannot assert a fake id for a key.
Safety-number comparison (Verify button) is the only thing that sets "Verified".

## Known limitations (honest list)
- NOT implemented: real translation (settings only report availability), approximate location, server-side blocking, offline queue / closed-tab push, forward secrecy, auth-attempt throttling by IP, per-connection-creation rate limit.
- Chat history is in tab memory only (ephemeral). Offline recipients get no message; sender sees failure + retry.
- Private key is stored as JWK in localStorage (XSS would expose it). Connect uses proof-of-possession (see SECURITY.md); no IP-based auth throttling.
- Single global Durable Object, capped at 200 sockets. Rate limit 40 frames/10s per socket.
- Duplicate display names are allowed (list shows an id suffix); identity, not name, is what matters.
- Clearing browser data destroys the identity; there is no recovery. Blocking can be evaded with a new identity.
- Free-plan quotas must be checked at https://developers.cloudflare.com/durable-objects/platform/pricing/ before launch.

## Tests
`npm test` runs crypto tests and Hub tests (fake sockets in Node: auth, spoofing, replay, expiry, routing, ack forgery, reactions, limits, presence). Not run: wrangler dev, real browsers, deploy.

## Added in v0.2
- **Images:** JPEG/PNG/WebP picked (<=8 MB, <=8000 px), decoded to verify content, re-encoded as JPEG <=150 KB (strips metadata/SVG/animation), previewed, then sent as <=25 encrypted chunks (AES-GCM, AAD binds each chunk id) over the WebSocket relay. Nothing is stored on the server; recipient must be online. Receiver validates indices, duplicates, size, JPEG signature and decodability; incomplete transfers expire after 60 s. Object URLs are revoked on deletion.
- **History:** IndexedDB, per identity, survives refresh. Stored UNENCRYPTED at rest (anyone with the browser profile can read it); lost if site data is cleared; not synced across devices. Per-chat and delete-all with confirmation; Back never deletes.
- **Location:** explicit 📍 action + confirm + browser permission; precise only, encrypted, sent once, needs HTTPS. Never in presence.
- **Notifications:** sound, vibration, browser notifications (permission requested only on enabling), per-chat mute. Foreground only; no service worker/push. Notification text is generic.
- **Origin:** missing or foreign Origin is rejected (not a substitute for the proof-of-possession auth).
- Reactions/receipts on images use chunk 0's id. Retrying a failed text message reuses its id; if the server already routed it, the retry is refused as a duplicate.
