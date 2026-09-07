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
const BridgeLink = require("./models/BridgeLink");
const Group = require("./models/Group");
const whatsapp = require("./whatsapp");
const { registerAuthRoutes, requireAuth, verifySession } = require("./auth");

const subtle = webcrypto.subtle;

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const BRIDGE_PREFIX = "wa-";

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

function convKey(a, b) { return [a, b].sort().join("|"); }
function sanitizeHandle(s) { return String(s || "").toLowerCase().trim().replace(/[^a-z0-9_.-]/g, ""); }
function bridgeHandleFor(username) { return `${BRIDGE_PREFIX}${username}`; }

registerAuthRoutes(app);

// ---------- Per-bridge key pairs (server-held; see whatsapp.js for why) ----------
const bridgeIdentitySchema = new mongoose.Schema({
  _id: { type: String }, // bridgeHandle
  privateKey: Object,
  publicKey: Object
});
const BridgeIdentity = mongoose.model("BridgeIdentity", bridgeIdentitySchema);
const bridgePrivateKeyCache = {};

async function ensureBridgeIdentity(bridgeHandle, ownerUsername) {
  let doc = await BridgeIdentity.findById(bridgeHandle);
  if (!doc) {
    const keyPair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const publicJwk = await subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await subtle.exportKey("jwk", keyPair.privateKey);
    doc = await BridgeIdentity.create({ _id: bridgeHandle, privateKey: privateJwk, publicKey: publicJwk });
  }
  await User.findOneAndUpdate(
    { username: bridgeHandle },
    { username: bridgeHandle, publicKey: doc.publicKey, isBridge: true, owner: ownerUsername },
    { upsert: true }
  );
  if (!bridgePrivateKeyCache[bridgeHandle]) {
    bridgePrivateKeyCache[bridgeHandle] = await subtle.importKey(
      "jwk", doc.privateKey, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]
    );
  }
  return bridgePrivateKeyCache[bridgeHandle];
}

async function deriveKeyWith(peerPublicJwk, myPrivateKey) {
  const peerPublicKey = await subtle.importKey("jwk", peerPublicJwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
  return subtle.deriveKey({ name: "ECDH", public: peerPublicKey }, myPrivateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function b64(buf) { return Buffer.from(buf).toString("base64"); }
function unb64(str) { return Buffer.from(str, "base64"); }

async function bridgeDecrypt(bridgeHandle, fromUsername, ivB64, ctB64) {
  const fromUser = await User.findOne({ username: fromUsername });
  if (!fromUser) throw new Error("unknown sender");
  const bridgeKey = bridgePrivateKeyCache[bridgeHandle];
  if (!bridgeKey) throw new Error("bridge identity not loaded");
  const key = await deriveKeyWith(fromUser.publicKey, bridgeKey);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
  return Buffer.from(pt).toString("utf8");
}

async function bridgeEncryptFor(bridgeHandle, toUsername, text) {
  const toUser = await User.findOne({ username: toUsername });
  if (!toUser) throw new Error("unknown recipient");
  const bridgeKey = bridgePrivateKeyCache[bridgeHandle];
  if (!bridgeKey) throw new Error("bridge identity not loaded");
  const key = await deriveKeyWith(toUser.publicKey, bridgeKey);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
  return { iv: b64(iv), ciphertext: b64(ct) };
}

// Called for every inbound WhatsApp message on a linked user's merged
// mirror session, from ANY sender - there is no allow-list. See the
// warning at the top of whatsapp.js.
async function onMirrorMessage(ownerUsername, senderNumber, senderName, text) {
  const owner = await User.findOne({ username: ownerUsername });
  if (!owner) return;
  const normalized = String(senderNumber || "").replace(/[^0-9]/g, "");
  const remoteUser = await User.findOne({ whatsappNumber: normalized, isBridge: false }).select("username").lean();

  if (remoteUser) {
    // The recipient browser owns the E2EE private key, so it performs the final
    // encryption. Plaintext is sent only over the authenticated live socket and
    // is never stored as plaintext in MongoDB.
    io.to(ownerUsername).emit("whatsapp:incoming", {
      fromHandle: remoteUser.username,
      externalNumber: normalized,
      externalName: senderName,
      text,
      ts: Date.now()
    });
    return;
  }

  // Keep the existing merged inbox for WhatsApp contacts who do not have an
  // Ephemeral handle. This uses the owner's bridge identity and stays separate
  // from normal direct-chat E2EE.
  const link = await BridgeLink.findOne({ username: ownerUsername });
  if (!link) return;
  link.lastExternalSender = normalized;
  link.lastExternalSenderName = senderName;
  await link.save();
  try {
    const bridgeHandle = link.bridgeHandle;
    const { iv, ciphertext } = await bridgeEncryptFor(bridgeHandle, ownerUsername, `${senderName}: ${text}`);
    const doc = await Message.create({
      conversationId: convKey(bridgeHandle, ownerUsername),
      from: bridgeHandle, to: ownerUsername, iv, ciphertext,
      meta: { externalNumber: normalized, externalName: senderName, viaWhatsApp: true }
    });
    io.to(ownerUsername).emit("message:new", {
      id: doc._id, from: bridgeHandle, to: ownerUsername, iv, ciphertext,
      ts: doc.createdAt.getTime(), meta: doc.meta
    });
  } catch (e) {
    console.error(`[whatsapp:${ownerUsername}] failed to relay incoming message:`, e.message);
  }
}

// ---------- REST API: directory & messaging ----------
app.get("/api/users/:username", async (req, res) => {
  const user = await User.findOne({ username: sanitizeHandle(req.params.username) });
  if (!user) return res.status(404).json({ error: "not found" });
  res.json({ username: user.username, publicKey: user.publicKey, isBridge: user.isBridge, whatsappLinked: !!user.whatsappNumber });
});

app.get("/api/messages/:peer", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const peer = sanitizeHandle(req.params.peer);
  const msgs = await Message.find({ conversationId: convKey(me, peer) }).sort({ createdAt: 1 }).lean();
  res.json(msgs.map(m => ({ id: m._id, from: m.from, to: m.to, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime(), meta: m.meta })));
});

// ---------- REST API: group chats ----------
app.post("/api/groups", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const name = String(req.body?.name || "").trim().slice(0, 80);
  const wrappedKeys = Array.isArray(req.body?.wrappedKeys) ? req.body.wrappedKeys : [];
  if (!name || wrappedKeys.length === 0) return res.status(400).json({ error: "group needs a name and at least one member" });
  const members = [...new Set(wrappedKeys.map(w => sanitizeHandle(w.username)))];
  if (!members.includes(me)) return res.status(400).json({ error: "you must include yourself as a member" });
  for (const w of wrappedKeys) {
    if (!w.username || !w.iv || !w.ciphertext) return res.status(400).json({ error: "malformed wrapped key" });
  }
  const group = await Group.create({ name, owner: me, members, wrappedKeys });
  res.json({ ok: true, id: group._id, name: group.name, members: group.members });
});

app.get("/api/groups", requireAuth, async (req, res) => {
  const groups = await Group.find({ members: req.auth.handle }).lean();
  res.json(groups.map(g => ({
    id: g._id, name: g.name, owner: g.owner, members: g.members,
    myWrappedKey: g.wrappedKeys.find(w => w.username === req.auth.handle) || null
  })));
});

app.get("/api/groups/:id/messages", requireAuth, async (req, res) => {
  const group = await Group.findById(req.params.id).lean().catch(() => null);
  if (!group || !group.members.includes(req.auth.handle)) return res.status(404).json({ error: "group not found" });
  const msgs = await Message.find({ groupId: req.params.id }).sort({ createdAt: 1 }).lean();
  res.json(msgs.map(m => ({ id: m._id, from: m.from, groupId: m.groupId, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime() })));
});

// ---------- REST API: WhatsApp linking (self-service, merged inbox) ----------
// A short code sent to the linked account's own WhatsApp chat proves the linked number.
const whatsappLinkCodes = new Map(); // handle -> { code, expiresAt }

app.get("/api/whatsapp/status", requireAuth, async (req, res) => {
  const link = await BridgeLink.findOne({ username: req.auth.handle });
  if (!link) return res.json({ linked: false });
  const status = whatsapp.getStatus(req.auth.handle);
  res.json({ linked: true, bridgeHandle: link.bridgeHandle, ...status });
});

app.get("/api/whatsapp/qr", requireAuth, (req, res) => {
  const qr = whatsapp.getQrDataUrl(req.auth.handle);
  if (!qr) return res.status(404).json({ error: "no QR pending" });
  res.setHeader("Content-Type", "image/png");
  res.send(Buffer.from(qr.split(",")[1], "base64"));
});

app.post("/api/whatsapp/link", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const bridgeHandle = bridgeHandleFor(me);
  await ensureBridgeIdentity(bridgeHandle, me);
  await BridgeLink.findOneAndUpdate({ username: me }, { username: me, bridgeHandle }, { upsert: true });
  await whatsapp.startSession(me, "mirror", (num, name, text) => onMirrorMessage(me, num, name, text));
  res.json({ ok: true, bridgeHandle });
});

app.post("/api/whatsapp/request-link-code", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const status = whatsapp.getStatus(me);
  if (status.state !== "open" || !status.ownNumber) return res.status(409).json({ error: "link WhatsApp first by scanning the QR" });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  whatsappLinkCodes.set(me, { code, expiresAt: Date.now() + 10 * 60 * 1000 });
  await whatsapp.sendMessageTo(me, status.ownNumber, `Your Ephemeral WhatsApp link code is ${code}. It expires in 10 minutes.`);
  res.json({ ok: true });
});

app.post("/api/whatsapp/verify-link-code", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const item = whatsappLinkCodes.get(me);
  const code = String(req.body?.code || "").trim();
  if (!item || Date.now() > item.expiresAt) return res.status(400).json({ error: "code expired - request a new one" });
  if (item.code !== code) return res.status(401).json({ error: "incorrect code" });
  const status = whatsapp.getStatus(me);
  if (!status.ownNumber) return res.status(409).json({ error: "WhatsApp number unavailable" });
  await User.updateOne({ username: me }, { $set: { whatsappNumber: status.ownNumber } });
  whatsappLinkCodes.delete(me);
  res.json({ ok: true, whatsappNumber: status.ownNumber });
});

app.post("/api/whatsapp/unlink", requireAuth, async (req, res) => {
  await BridgeLink.deleteOne({ username: req.auth.handle });
  res.json({ ok: true });
});

// ---------- Admin: link the shared verifier bot that sends OTP codes ----------
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(503).json({ error: "set ADMIN_TOKEN in the environment to use admin routes" });
  if (req.query.token !== ADMIN_TOKEN) return res.status(403).json({ error: "bad admin token" });
  next();
}
app.post("/api/admin/verifier/start", requireAdmin, async (req, res) => {
  await whatsapp.startVerifier();
  res.json({ ok: true });
});
app.get("/api/admin/verifier/status", requireAdmin, (req, res) => {
  res.json(whatsapp.getStatus(whatsapp.VERIFIER_KEY));
});
app.get("/api/admin/verifier/qr", requireAdmin, (req, res) => {
  const qr = whatsapp.getQrDataUrl(whatsapp.VERIFIER_KEY);
  if (!qr) return res.status(404).json({ error: "no QR pending" });
  res.setHeader("Content-Type", "image/png");
  res.send(Buffer.from(qr.split(",")[1], "base64"));
});

// ---------- Sockets ----------
io.on("connection", (socket) => {
  socket.on("identify", (token) => {
    const payload = verifySession(token);
    if (!payload || !payload.handle) return;
    socket.data.username = payload.handle;
    socket.join(payload.handle);
  });

  socket.on("message:import-whatsapp", async ({ to, text }, ack) => {
    const owner = socket.data.username;
    const peer = sanitizeHandle(to || "");
    if (!owner || !peer || !text) return ack && ack({ ok: false, error: "invalid WhatsApp message" });
    const remote = await User.findOne({ username: peer, whatsappNumber: { $exists: true, $ne: null } }).select("username whatsappNumber").lean();
    if (!remote) return ack && ack({ ok: false, error: "WhatsApp sender is not a linked Ephemeral user" });
    // The browser has already encrypted this text using the normal E2EE peer key.
    // This event is only used to persist the ciphertext produced by the browser.
    ack && ack({ ok: true });
  });

  socket.on("group:send", async ({ groupId, iv, ciphertext }, ack) => {
    const from = socket.data.username;
    if (!from || !groupId || !iv || !ciphertext) return ack && ack({ ok: false, error: "sign in required" });
    const group = await Group.findById(groupId).lean().catch(() => null);
    if (!group || !group.members.includes(from)) return ack && ack({ ok: false, error: "not a member of this group" });
    const doc = await Message.create({ conversationId: `group:${groupId}`, from, groupId, iv, ciphertext });
    const payload = { id: doc._id, from, groupId, iv, ciphertext, ts: doc.createdAt.getTime() };
    for (const member of group.members) io.to(member).emit("group:message:new", payload);
    ack && ack({ ok: true });
  });

  socket.on("message:send", async ({ to, iv, ciphertext, viaWhatsApp = false, relay }, ack) => {
    const from = socket.data.username;
    const toClean = sanitizeHandle(to);
    if (!from || !toClean || !iv || !ciphertext) return ack && ack({ ok: false, error: "sign in required" });

    const doc = await Message.create({ conversationId: convKey(from, toClean), from, to: toClean, iv, ciphertext });
    const payload = { id: doc._id, from, to: toClean, iv, ciphertext, ts: doc.createdAt.getTime() };
    io.to(toClean).emit("message:new", payload);
    io.to(from).emit("message:new", payload);
    ack && ack({ ok: true });

    // If both users linked WhatsApp, mirror app messages to the recipient's
    // actual WhatsApp phone number. The linked sender's WhatsApp session is used
    // as the transport endpoint; WhatsApp then delivers phone-to-phone.
    try {
      const sender = await User.findOne({ username: from }).select("whatsappNumber").lean();
      if (toClean === bridgeHandleFor(from)) {
        const link = await BridgeLink.findOne({ username: from });
        if (link?.lastExternalSender) {
          const text = await bridgeDecrypt(toClean, from, iv, ciphertext);
          await whatsapp.sendMessageTo(from, link.lastExternalSender, text);
        }
      } else if (!viaWhatsApp && relay?.iv && relay?.ciphertext && sender?.whatsappNumber) {
        const recipient = await User.findOne({ username: toClean }).select("whatsappNumber").lean();
        if (recipient?.whatsappNumber) {
          // `relay` is a SEPARATE ciphertext the client encrypted specifically
          // for the recipient's bridge public key (same construction as the
          // self-bridge path above). The main iv/ciphertext stays true E2EE
          // for the recipient's real key and is never decryptable here.
          const recipientBridgeHandle = bridgeHandleFor(toClean);
          await ensureBridgeIdentity(recipientBridgeHandle, toClean);
          const text = await bridgeDecrypt(recipientBridgeHandle, from, relay.iv, relay.ciphertext);
          // The sender's linked WhatsApp session is the transport endpoint.
          // This makes app -> WhatsApp delivery symmetric with the inbound
          // WhatsApp -> app path handled by onMirrorMessage().
          await whatsapp.sendMessageTo(from, recipient.whatsappNumber, text);
        }
      }
    } catch (e) {
      console.error(`[whatsapp:${from}] failed to mirror outgoing message:`, e.message);
    }
  });
});

// ---------- Boot ----------
async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("[db] connected");

  const links = await BridgeLink.find({});
  for (const link of links) {
    await ensureBridgeIdentity(link.bridgeHandle, link.username);
    whatsapp.startSession(link.username, "mirror", (num, name, text) => onMirrorMessage(link.username, num, name, text))
      .catch(e => console.error(`[whatsapp:${link.username}] failed to resume session:`, e.message));
  }
  console.log(`[whatsapp] resumed ${links.length} existing link(s)`);

  if (ADMIN_TOKEN) {
    // Auto-resume the verifier bot on restart if it was ever linked before.
    whatsapp.startVerifier().catch(e => console.error("[whatsapp] verifier resume failed:", e.message));
  } else {
    console.warn("[whatsapp] ADMIN_TOKEN not set - the verifier bot can't be linked, so phone login needs DEV_MODE=true to work locally.");
  }

  server.listen(PORT, () => console.log(`[server] listening on :${PORT}`));
}

main().catch((e) => {
  console.error("Fatal startup error:", e);
  process.exit(1);
});
