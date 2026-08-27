# Deploying AegisChat

Two independent pieces:

1. **The relay** — a small Node service. Untrusted for confidentiality and
   metadata by design, but it still needs TLS (transport integrity, availability)
   and sensible operational hygiene.
2. **The client** — a static bundle (web) or a native app (Tauri). It just needs
   to know the relay's URL at build time.

You can run the relay and never touch the client build, or vice versa.

---

## 1. Relay

### Quick start (Docker + automatic TLS)

```bash
cd deploy
# edit Caddyfile: set your hostname + email
# edit/export AEGIS_ALLOWED_ORIGINS to the origin your client is served from
export AEGIS_ALLOWED_ORIGINS=https://app.example.org
docker compose up -d --build
```

Caddy terminates TLS on :443 and proxies HTTP + WebSocket to the relay on an
internal network. The relay container runs read-only, unprivileged, memory-capped.

### Without Docker

```bash
cd server
npm ci
npm run build
PORT=4000 AEGIS_ALLOWED_ORIGINS=https://app.example.org node dist/index.js
```

Put it behind nginx/Caddy/Traefik for TLS. Make sure the proxy forwards
WebSocket upgrades on the same path (`/ws`).

### Environment

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `4000` | Listen port. |
| `AEGIS_ALLOWED_ORIGINS` | localhost dev origins | Comma-separated browser origins allowed by CORS. Requests with no `Origin` (non-browser) are allowed. |

### Operational notes

- **State is in RAM only.** Restarting the relay drops offline queues, the
  prekey directory, and groups. That is acceptable for the design (clients
  re-register on connect) but means no message loss protection beyond what
  clients retry. There is no database to secure or subpoena.
- **The audit log** (`GET /api/audit`) is unauthenticated and in-memory
  (bounded, ~200 entries). Post-sealed-sender it does not record 1:1
  sender/recipient. It *does* record group-creation events with the creator and
  member names — consider disabling that route at the proxy if that metadata
  matters for your users, until blind group setup lands.
- **No rate limiting** is built in. Add it at the proxy (Caddy `rate_limit`,
  nginx `limit_req`) — at minimum on `/api/keys/register`, `/api/attachments/*`,
  and new WebSocket connections.
- **Logs.** The relay writes connection/routing lines to stdout. Configure your
  container/host to **not** persist these, or scrub them. They contain
  usernames (from `AUTH`) even though sealed routing does not.
- **Jurisdiction / hosting.** The relay sees IP addresses, connection timing,
  and (currently) group rosters. Choose hosting accordingly. A hidden service
  (Tor onion) or a fronted CDN in front of the relay meaningfully reduces what a
  network observer learns; point clients at it via the relay-URL override.
- **Capacity.** Defaults: 500 queued msgs/recipient, 2000 stored attachments
  (24h TTL), 5000 groups, 256 KB JSON bodies, 25 MB uploads, 2 MB WS frames.
  Tune in `server/src/relay.ts` / `index.ts`.

---

## 2. Client

### Web

```bash
cd client
VITE_RELAY_URL=https://relay.example.org npm run build
# serve ./dist as static files from https://app.example.org
```

The bundle is fully static. Serve it over HTTPS with:

- `Content-Security-Policy` at least as strict as the Tauri one in
  `src-tauri/tauri.conf.json` — `script-src 'self'`, `connect-src 'self'
  https://relay.example.org wss://relay.example.org`, `object-src 'none'`.
- Subresource Integrity or a pinned hash if you can — the delivery channel for
  the JS **is** part of the trusted computing base. A reproducible build +
  published hash lets users check what they ran.
- No third-party scripts, analytics, tag managers, or fonts from other origins.

### Desktop (Tauri)

```bash
cd client
VITE_RELAY_URL=https://relay.example.org npm run tauri build
```

Update `connect-src` in `src-tauri/tauri.conf.json` to include your relay's
`https://` and `wss://` origins before building. Sign the installer.

### Mobile

See [`MOBILE_PACKAGING_GUIDE.md`](MOBILE_PACKAGING_GUIDE.md). Same
`VITE_RELAY_URL` + CSP considerations apply.

---

## 3. Before you point real users at it

- [ ] Independent security review (see `../SECURITY.md`).
- [ ] Rate limiting at the proxy.
- [ ] Log retention set to none / scrubbed.
- [ ] CSP verified in the deployed client (not just the dev config).
- [ ] A published, reproducible client build hash.
- [ ] A working vulnerability-disclosure inbox.
- [ ] Decide what you tell users about the known non-guarantees in
      `THREAT_MODEL.md` §5.
