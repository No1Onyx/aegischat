import { randomUUID } from 'crypto';
import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import { KeyDirectory } from './keyDirectory.js';
import { BlindRelay } from './relay.js';

const app = express();
const port = 4000;

// Restrict cross-origin access to the local dev client / packaged app shells.
// Override with AEGIS_ALLOWED_ORIGINS (comma-separated) for other deployments.
const ALLOWED_ORIGINS = (
  process.env.AEGIS_ALLOWED_ORIGINS ||
  'http://localhost:5173,http://127.0.0.1:5173,tauri://localhost,https://tauri.localhost'
).split(',').map((o) => o.trim());

app.use(cors({
  origin(origin, cb) {
    // Allow same-origin / non-browser callers (no Origin header) and the allowlist.
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed'));
  },
}));

// Bound request bodies. JSON control messages are tiny; only attachment uploads
// are large and they use their own express.raw limit below.
app.use(express.json({ limit: '256kb' }));

const keyDirectory = new KeyDirectory();
const relay = new BlindRelay();

// Health / Status
app.get('/api/status', (req, res) => {
  res.json({
    status: 'online',
    type: 'Zero-Knowledge Blind Relay',
    registeredUsers: keyDirectory.getAllUsers().length,
  });
});

// List all registered users
app.get('/api/users', (req, res) => {
  res.json({ users: keyDirectory.getAllUsers() });
});

// Register public key bundle
app.post('/api/keys/register', (req, res) => {
  const { username, identityPublicKey, signingPublicKey, signedPreKey, oneTimePreKeys } = req.body;

  if (!username || !identityPublicKey || !signingPublicKey || !signedPreKey) {
    return res.status(400).json({ error: 'Missing required cryptographic keys' });
  }

  const success = keyDirectory.registerUser(
    username,
    identityPublicKey,
    signingPublicKey,
    signedPreKey,
    oneTimePreKeys || []
  );

  return res.json({ success, username });
});

// Retrieve public key bundle for initiating an encrypted session
app.get('/api/keys/:username', (req, res) => {
  const { username } = req.params;
  const bundle = keyDirectory.getKeyBundle(username);

  if (!bundle) {
    return res.status(404).json({ error: `User ${username} not found in directory` });
  }

  return res.json(bundle);
});

// Retrieve server audit logs (to prove no plaintexts are held)
app.get('/api/audit', (req, res) => {
  res.json({ logs: relay.getAuditLogs() });
});

// Upload opaque encrypted attachment (Zero-Knowledge: server sees only encrypted noise)
app.post('/api/attachments/upload', express.raw({ type: '*/*', limit: '25mb' }), (req, res) => {
  if (!req.body || (req.body as Buffer).length === 0) {
    return res.status(400).json({ error: 'No payload provided' });
  }

  const contentType = req.headers['content-type'] || 'application/octet-stream';
  const attachmentId = relay.storeAttachment(req.body as Buffer, contentType);

  return res.json({ attachmentId });
});

// Download opaque encrypted attachment
app.get('/api/attachments/:id', (req, res) => {
  const { id } = req.params;
  const att = relay.getAttachment(id);

  if (!att) {
    return res.status(404).json({ error: 'Attachment not found or expired' });
  }

  res.setHeader('Content-Type', att.contentType);
  res.setHeader('Content-Length', att.data.length);
  return res.send(att.data);
});

// Create a secret group
app.post('/api/groups/create', (req, res) => {
  const { id, name, creator, members } = req.body;
  if (!name || !creator || !Array.isArray(members)) {
    return res.status(400).json({ error: 'Missing required group parameters' });
  }
  if (members.length > 512) {
    return res.status(400).json({ error: 'Group too large' });
  }

  const groupId = typeof id === 'string' && id ? id : 'grp_' + randomUUID();
  try {
    const metadata = relay.createGroup(groupId, name, creator, members);
    return res.json(metadata);
  } catch (err) {
    return res.status(503).json({ error: (err as Error).message });
  }
});

// List groups for a user
app.get('/api/groups/user/:username', (req, res) => {
  const { username } = req.params;
  const groups = relay.getGroupsForUser(username);
  return res.json({ groups });
});

// Get specific group info
app.get('/api/groups/:id', (req, res) => {
  const { id } = req.params;
  const group = relay.getGroup(id);
  if (!group) {
    return res.status(404).json({ error: 'Group not found' });
  }
  return res.json(group);
});

// Create HTTP and WebSocket servers
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2 * 1024 * 1024 });

wss.on('connection', (ws: WebSocket) => {
  ws.on('message', (messageData: string) => {
    try {
      const parsed = JSON.parse(messageData.toString());

      switch (parsed.type) {
        case 'AUTH':
          if (parsed.username) {
            relay.registerClient(parsed.username, ws, parsed.blindToken);
          }
          break;

        case 'ENVELOPE':
          if (parsed.payload) {
            const result = relay.routeEnvelope(parsed.payload);
            ws.send(JSON.stringify({ type: 'ROUTED', envelopeId: parsed.payload.id, result }));
          }
          break;

        case 'SEALED_ENVELOPE':
          if (parsed.payload) {
            const result = relay.routeSealedEnvelope(parsed.payload);
            ws.send(JSON.stringify({ type: 'ROUTED', envelopeId: parsed.payload.id, result }));
          }
          break;

        case 'GROUP_ENVELOPE':
          if (parsed.payload) {
            const result = relay.routeGroupEnvelope(parsed.payload);
            ws.send(JSON.stringify({ type: 'GROUP_ROUTED', envelopeId: parsed.payload.id, result }));
          }
          break;

        case 'ACK':
          if (parsed.envelopeId) {
            relay.acknowledgeDelivery(parsed.envelopeId);
          }
          break;

        case 'SUBSCRIBE_AUDIT':
          relay.registerAuditSubscriber(ws);
          break;

        default:
          console.warn(`[Relay] Unknown message type: ${parsed.type}`);
      }
    } catch (err) {
      console.error('[Relay] Error handling message:', err);
    }
  });

  ws.on('close', () => {
    relay.unregisterClient(ws);
  });
});

server.listen(port, () => {
  console.log(`[AegisChat Relay] Server running on http://localhost:${port}`);
  console.log(`[AegisChat Relay] WebSocket endpoint at ws://localhost:${port}/ws`);
});
