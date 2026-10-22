# SENDORA privacy
- **Browser localStorage:** identity key pair, display name, settings, block list, verified list. Clearing browser data destroys the identity permanently.
- **IndexedDB (this browser):** chat history and received images, unencrypted at rest, per identity; lost if site data is cleared; not synced. Deleting locally never removes the other person's copy; printed copies are outside the encrypted chat.
- **Server:** keeps no messages and has no database; online presence (id, name, public key) and a short in-memory routing record live only in the Durable Object while connected. No offline queue: messages to offline users fail.
- **Images/location:** sent end-to-end encrypted, relayed live and never stored by the server. Location is sent only after you confirm in a chat. **Not implemented:** translation.
- **Notifications:** foreground only; no push service.
- No analytics or tracking.
