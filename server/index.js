require("dotenv").config();

const path = require("path");
const express = require("express");
const cors = require("cors");
const http = require("http");
const mongoose = require("mongoose");
const { Server } = require("socket.io");
const { webcrypto } = require("crypto");

const User = require("./models/User");
const Message = require("./models/Message");
const whatsapp = require("./whatsapp");

const subtle = webcrypto.subtle;

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const ENABLE_WHATSAPP = String(process.env.ENABLE_WHATSAPP || "false") === "true";
const WHATSAPP_BRIDGE_TARGET = process.env.WHATSAPP_BRIDGE_TARGET || "";
const WHATSAPP_APP_USERNAME = (process.env.WHATSAPP_APP_USERNAME || "").toLowerCase();
const BRIDGE_USERNAME = "whatsapp";

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI in your environment. See .env.example.");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "..", "public")));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

function convKey(a, b) {
  return [a, b].sort().join("|");
}

// ---------- Bridge identity (server-held keypair for the "whatsapp" user) ----------
// Kept in Mongo (not on disk) so it survives redeploys on hosts with an
// ephemeral filesystem, like Render's free tier.
const bridgeIdentitySchema = new mongoose.Schema({
  _id: { type: String, default: "bridge" },
  privateKey: Object,
  publicKey: Object
});
const BridgeIdentity = mongoose.model("BridgeIdentity", bridgeIdentitySchema);

let bridgePrivateKey = null; // CryptoKey

async function ensureBridgeIdentity() {
  let doc = await BridgeIdentity.findById("bridge");
  if (!doc) {
    const keyPair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await subtle.exportKey("jwk", keyPair.privateKey);
    doc = await BridgeIdentity.create({ _id: "bridge", privateKey: privateJwk, publicKey: publicJwk });
    await User.findOneAndUpdate(
      { username: BRIDGE_USERNAME },
      { username: BRIDGE_USERNAME, publicKey: publicJwk, isBridge: true },
      { upsert: true }
    );
  }
  bridgePrivateKey = await subtle.importKey("jwk", doc.privateKey, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
}

async function deriveKeyWith(peerPublicJwk, myPrivateKey) {
  const peerPublicKey = await subtle.importKey("jwk", peerPublicJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
  return subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    myPrivateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function b64(buf) { return Buffer.from(buf).toString("base64"); }
function unb64(str) { return Buffer.from(str, "base64"); }

async function bridgeDecrypt(fromUsername, ivB64, ctB64) {
  const fromUser = await User.findOne({ username: fromUsername });
  if (!fromUser) throw new Error("unknown sender");
  const key = await deriveKeyWith(fromUser.publicKey, bridgePrivateKey);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
  return Buffer.from(pt).toString("utf8");
}

async function bridgeEncryptFor(toUsername, text) {
  const toUser = await User.findOne({ username: toUsername });
  if (!toUser) throw new Error("unknown recipient");
  const key = await deriveKeyWith(toUser.publicKey, bridgePrivateKey);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
  return { iv: b64(iv), ciphertext: b64(ct) };
}

// ---------- REST API ----------
app.post("/api/register", async (req, res) => {
  const { username, publicKey } = req.body || {};
  if (!username || !publicKey) return res.status(400).json({ error: "username and publicKey are required" });
  const clean = String(username).toLowerCase().trim();
  if (!/^[a-z0-9_.-]{1,24}$/.test(clean)) return res.status(400).json({ error: "invalid handle" });
  if (clean === BRIDGE_USERNAME) return res.status(409).json({ error: "that handle is reserved" });

  const existing = await User.findOne({ username: clean });
  if (existing) return res.status(409).json({ error: "handle already taken" });

  await User.create({ username: clean, publicKey });
  res.json({ ok: true, username: clean });
});

app.get("/api/users/:username", async (req, res) => {
  const user = await User.findOne({ username: String(req.params.username).toLowerCase() });
  if (!user) return res.status(404).json({ error: "not found" });
  res.json({ username: user.username, publicKey: user.publicKey, isBridge: user.isBridge });
});

// Minimal, handle-based "auth": ?me=<your handle>. There is no password -
// this mirrors the original artifact's trust model. Add real auth before
// putting anything sensitive behind this.
app.get("/api/messages/:peer", async (req, res) => {
  const me = String(req.query.me || "").toLowerCase();
  const peer = String(req.params.peer).toLowerCase();
  if (!me) return res.status(400).json({ error: "missing ?me=<your handle>" });
  const msgs = await Message.find({ conversationId: convKey(me, peer) }).sort({ createdAt: 1 }).lean();
  res.json(msgs.map(m => ({ id: m._id, from: m.from, to: m.to, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime() })));
});

app.get("/api/whatsapp/status", (req, res) => {
  res.json({ enabled: ENABLE_WHATSAPP, ...whatsapp.getStatus() });
});

app.get("/api/whatsapp/qr", (req, res) => {
  const qr = whatsapp.getQrDataUrl();
  if (!qr) return res.status(404).json({ error: "no QR pending - either already linked, disabled, or not started yet" });
  const img = Buffer.from(qr.split(",")[1], "base64");
  res.setHeader("Content-Type", "image/png");
  res.send(img);
});

// ---------- Sockets ----------
io.on("connection", (socket) => {
  socket.on("identify", (username) => {
    socket.data.username = String(username || "").toLowerCase();
    if (socket.data.username) socket.join(socket.data.username);
  });

  socket.on("message:send", async ({ to, iv, ciphertext }, ack) => {
    const from = socket.data.username;
    if (!from || !to || !iv || !ciphertext) return ack && ack({ ok: false, error: "bad payload" });

    const doc = await Message.create({ conversationId: convKey(from, to), from, to, iv, ciphertext });
    const payload = { id: doc._id, from, to, iv, ciphertext, ts: doc.createdAt.getTime() };
    io.to(to).emit("message:new", payload);
    io.to(from).emit("message:new", payload);
    ack && ack({ ok: true });

    if (ENABLE_WHATSAPP && to === BRIDGE_USERNAME) {
      try {
        const text = await bridgeDecrypt(from, iv, ciphertext);
        await whatsapp.sendWhatsAppMessage(text);
      } catch (e) {
        console.error("[whatsapp] failed to relay outgoing message:", e.message);
      }
    }
  });
});

// ---------- Boot ----------
async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("[db] connected");

  await ensureBridgeIdentity();
  console.log(`[bridge] identity ready (handle: "${BRIDGE_USERNAME}")`);

  if (ENABLE_WHATSAPP) {
    if (!WHATSAPP_APP_USERNAME) {
      console.warn("[whatsapp] ENABLE_WHATSAPP is true but WHATSAPP_APP_USERNAME is not set - incoming WhatsApp messages have nowhere to go.");
    }
    await whatsapp.initWhatsApp({
      target: WHATSAPP_BRIDGE_TARGET,
      onMessage: async (text) => {
        if (!WHATSAPP_APP_USERNAME) return;
        try {
          const { iv, ciphertext } = await bridgeEncryptFor(WHATSAPP_APP_USERNAME, text);
          const doc = await Message.create({
            conversationId: convKey(BRIDGE_USERNAME, WHATSAPP_APP_USERNAME),
            from: BRIDGE_USERNAME, to: WHATSAPP_APP_USERNAME, iv, ciphertext
          });
          io.to(WHATSAPP_APP_USERNAME).emit("message:new", {
            id: doc._id, from: BRIDGE_USERNAME, to: WHATSAPP_APP_USERNAME, iv, ciphertext, ts: doc.createdAt.getTime()
          });
        } catch (e) {
          console.error("[whatsapp] failed to relay incoming message:", e.message);
        }
      }
    });
  }

  server.listen(PORT, () => console.log(`[server] listening on :${PORT}`));
}

main().catch((e) => {
  console.error("Fatal startup error:", e);
  process.exit(1);
});
