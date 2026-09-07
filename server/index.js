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
const Group = require("./models/Group");
const BridgeLink = require("./models/BridgeLink");
const whatsapp = require("./whatsapp");
const { registerAuthRoutes, requireAuth, verifySession, normalizePhone } = require("./auth");

const subtle = webcrypto.subtle;

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const BRIDGE_PREFIX = "wa-";

const onlineCounts = new Map();

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

registerAuthRoutes(app, {
  onHandleRequest: (handle, request) => io.to(handle).emit("auth:handle-request", request)
});

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
  const link = await BridgeLink.findOne({ username: ownerUsername });
  if (!link) return;
  link.lastExternalSender = senderNumber;
  link.lastExternalSenderName = senderName;
  await link.save();
  try {
    const { iv, ciphertext } = await bridgeEncryptFor(link.bridgeHandle, ownerUsername, `${senderName}: ${text}`);
    const doc = await Message.create({
      conversationId: convKey(link.bridgeHandle, ownerUsername),
      from: link.bridgeHandle, to: ownerUsername, iv, ciphertext,
      meta: { externalNumber: senderNumber, externalName: senderName }
    });
    io.to(ownerUsername).emit("message:new", {
      id: doc._id, from: link.bridgeHandle, to: ownerUsername, iv, ciphertext, ts: doc.createdAt.getTime(),
      meta: doc.meta
    });
  } catch (e) {
    console.error(`[whatsapp:${ownerUsername}] failed to relay incoming message:`, e.message);
  }
}

// ---------- REST API: directory & messaging ----------
// ---------- Ephemeral retention helpers ----------
const FIFTEEN_MESSAGE_LIMIT = 15;

async function pruneConversation(conversationId) {
  const keep = await Message.find({ conversationId })
    .sort({ createdAt: -1 })
    .limit(FIFTEEN_MESSAGE_LIMIT)
    .select("_id")
    .lean();
  if (keep.length < FIFTEEN_MESSAGE_LIMIT) return;
  await Message.deleteMany({
    conversationId,
    _id: { $nin: keep.map(m => m._id) }
  });
}

async function pruneDirectForUser(username) {
  const escaped = username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const ids = await Message.find({
    conversationId: { $regex: `(^|\\|)${escaped}(\\||$)` }
  }).distinct("conversationId");
  for (const id of ids) await pruneConversation(id);
}

async function pruneGroupsForUser(username) {
  const groups = await Group.find({ members: username }).select("_id").lean();
  for (const group of groups) await pruneConversation(`group:${group._id}`);
}

async function userHasShortRetention(username) {
  const user = await User.findOne({ username }).select("deleteAfter15Messages").lean();
  return !!user?.deleteAfter15Messages;
}

async function shouldPruneDirect(from, to) {
  if (await userHasShortRetention(from)) return true;
  if (to && !to.startsWith("wa-") && await userHasShortRetention(to)) return true;
  return false;
}

app.get("/api/users/:username", async (req, res) => {
  const user = await User.findOne({ username: sanitizeHandle(req.params.username) });
  if (!user) return res.status(404).json({ error: "not found" });
  res.json({ username: user.username, publicKey: user.publicKey, isBridge: user.isBridge, lastSeenAt: user.lastSeenAt ? user.lastSeenAt.getTime() : null });
});

app.get("/api/messages/:peer", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const peer = sanitizeHandle(req.params.peer);
  const msgs = await Message.find({ conversationId: convKey(me, peer) }).sort({ createdAt: 1 }).lean();
  res.json(msgs.map(m => ({ id: m._id, from: m.from, to: m.to, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime(), meta: m.meta })));
});


// ---------- Presence, inbox metadata & groups ----------
app.get("/api/inbox", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const groups = await Group.find({ members: me }).select("_id name members createdAt").lean();
  const direct = await Message.find({
    conversationId: { $regex: `(^|\\|)${me.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}(\\||$)` }
  }).sort({ createdAt: -1 }).limit(500).lean();
  const latest = new Map();
  for (const m of direct) {
    if (m.conversationId.startsWith("group:")) continue;
    const other = m.from === me ? m.to : m.from;
    if (!latest.has(other)) latest.set(other, m);
  }
  res.json({
    direct: [...latest.entries()].map(([peer, m]) => ({ peer, id: m._id, from: m.from, to: m.to, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime() })),
    groups: groups.map(g => ({ id: String(g._id), name: g.name, members: g.members, createdAt: g.createdAt.getTime() }))
  });
});

app.get("/api/presence/:username", requireAuth, async (req, res) => {
  const username = sanitizeHandle(req.params.username);
  const user = await User.findOne({ username }).select("lastSeenAt").lean();
  res.json({ username, online: (onlineCounts.get(username) || 0) > 0, lastSeenAt: user?.lastSeenAt ? new Date(user.lastSeenAt).getTime() : null });
});

app.get("/api/settings", requireAuth, async (req, res) => {
  const user = await User.findOne({ username: req.auth.handle })
    .select("deleteAfter15Messages")
    .lean();
  res.json({ deleteAfter15Messages: !!user?.deleteAfter15Messages });
});

app.post("/api/settings", requireAuth, async (req, res) => {
  const enabled = req.body?.deleteAfter15Messages === true;
  await User.updateOne(
    { username: req.auth.handle },
    { $set: { deleteAfter15Messages: enabled } }
  );

  // Apply immediately when the user enables the setting.
  if (enabled) {
    await pruneDirectForUser(req.auth.handle);
    await pruneGroupsForUser(req.auth.handle);
  }

  res.json({ ok: true, deleteAfter15Messages: enabled });
});

app.post("/api/groups", requireAuth, async (req, res) => {
  const me = req.auth.handle;
  const name = String(req.body?.name || "").trim();
  const requestedMembers = Array.isArray(req.body?.members) ? req.body.members : [];
  const wrappedKeys = Array.isArray(req.body?.wrappedKeys) ? req.body.wrappedKeys : [];
  if (!name || name.length > 80) return res.status(400).json({ error: "group name must be 1-80 characters" });
  const members = [...new Set([me, ...requestedMembers.map(sanitizeHandle).filter(Boolean)])];
  if (members.length < 2) return res.status(400).json({ error: "add at least one other member" });
  if (members.length > 50) return res.status(400).json({ error: "groups are limited to 50 members" });
  const users = await User.find({ username: { $in: members }, isBridge: { $ne: true } }).select("username publicKey").lean();
  if (users.length !== members.length) return res.status(400).json({ error: "one or more handles do not exist" });
  const keyMap = new Map(wrappedKeys.map(k => [sanitizeHandle(k.username), k]));
  for (const member of members) {
    const wrapped = keyMap.get(member);
    if (!wrapped?.iv || !wrapped?.ciphertext) return res.status(400).json({ error: `missing encrypted group key for ${member}` });
  }
  const group = await Group.create({ name, owner: me, members, wrappedKeys: members.map(username => ({ username, iv: keyMap.get(username).iv, ciphertext: keyMap.get(username).ciphertext })) });
  const payload = { id: String(group._id), name: group.name, owner: group.owner, members: group.members, createdAt: group.createdAt.getTime() };
  for (const member of members) io.to(member).emit("group:created", payload);
  res.json({ ok: true, group: payload });
});

app.get("/api/groups", requireAuth, async (req, res) => {
  const groups = await Group.find({ members: req.auth.handle }).sort({ createdAt: -1 }).lean();
  res.json(groups.map(g => ({ id: String(g._id), name: g.name, owner: g.owner, members: g.members, createdAt: g.createdAt.getTime() })));
});

app.get("/api/groups/:id", requireAuth, async (req, res) => {
  const group = await Group.findOne({ _id: req.params.id, members: req.auth.handle }).lean();
  if (!group) return res.status(404).json({ error: "group not found" });
  const wrapped = group.wrappedKeys.find(k => k.username === req.auth.handle);
  res.json({ id: String(group._id), name: group.name, owner: group.owner, members: group.members, wrappedKey: wrapped || null, createdAt: group.createdAt.getTime() });
});

app.get("/api/groups/:id/messages", requireAuth, async (req, res) => {
  const group = await Group.findOne({ _id: req.params.id, members: req.auth.handle }).select("_id").lean();
  if (!group) return res.status(404).json({ error: "group not found" });
  const msgs = await Message.find({ conversationId: `group:${req.params.id}` }).sort({ createdAt: 1 }).lean();
  res.json(msgs.map(m => ({ id: m._id, from: m.from, to: m.to, iv: m.iv, ciphertext: m.ciphertext, ts: m.createdAt.getTime(), meta: m.meta })));
});

// ---------- REST API: WhatsApp linking (self-service, merged inbox) ----------
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
  socket.on("identify", async (token) => {
    const payload = verifySession(token);
    if (!payload || !payload.handle) return;
    socket.data.username = payload.handle;
    socket.join(payload.handle);
    onlineCounts.set(payload.handle, (onlineCounts.get(payload.handle) || 0) + 1);
    socket.data.presenceRegistered = true;
    const groups = await Group.find({ members: payload.handle }).select("_id").lean();
    groups.forEach(g => socket.join(`group:${g._id}`));
    io.emit("presence:update", { username: payload.handle, online: true, lastSeenAt: null });
    const presenceUsers = await User.find({ username: { $in: [...onlineCounts.keys()] } }).select("username lastSeenAt").lean();
    const seenMap = new Map(presenceUsers.map(u => [u.username, u.lastSeenAt ? new Date(u.lastSeenAt).getTime() : null]));
    socket.emit("presence:snapshot", [...onlineCounts.entries()].map(([username, count]) => ({ username, online: count > 0, lastSeenAt: seenMap.get(username) || null })));
  });

  socket.on("group:join", async (groupId, ack) => {
    const username = socket.data.username;
    if (!username || !mongoose.isValidObjectId(groupId)) return ack && ack({ ok: false, error: "invalid group" });
    const group = await Group.findOne({ _id: groupId, members: username }).select("_id").lean();
    if (!group) return ack && ack({ ok: false, error: "not a member" });
    socket.join(`group:${groupId}`);
    ack && ack({ ok: true });
  });

  socket.on("message:send", async ({ to, iv, ciphertext }, ack) => {
    try {
      const from = socket.data.username;
      const toClean = sanitizeHandle(to);
      if (!from || !toClean || !iv || !ciphertext) return ack && ack({ ok: false, error: "sign in required" });
      if (toClean === from) return ack && ack({ ok: false, error: "cannot message yourself" });
      if (!toClean.startsWith("wa-")) {
        const recipient = await User.findOne({ username: toClean }).select("username").lean();
        if (!recipient) return ack && ack({ ok: false, error: "recipient not found" });
      }
      const conversationId = convKey(from, toClean);
      const doc = await Message.create({ conversationId, from, to: toClean, iv, ciphertext });
      if (await shouldPruneDirect(from, toClean)) await pruneConversation(conversationId);
      const payload = { id: doc._id, from, to: toClean, iv, ciphertext, ts: doc.createdAt.getTime() };
      io.to(toClean).emit("message:new", payload);
      io.to(from).emit("message:new", payload);
      ack && ack({ ok: true });

      if (toClean === bridgeHandleFor(from)) {
        try {
          const link = await BridgeLink.findOne({ username: from });
          if (!link || !link.lastExternalSender) throw new Error("no WhatsApp contact to reply to yet");
          const text = await bridgeDecrypt(toClean, from, iv, ciphertext);
          const recipientPhone = String(link.lastExternalSender || "").replace(/[^0-9]/g, "");
          if (!recipientPhone) throw new Error("no valid WhatsApp recipient phone number");
          // WhatsApp delivery is addressed directly from the linked WhatsApp number
          // to the contact phone number. Baileys/WhatsApp provides transport E2EE;
          // the bridge itself is an endpoint and therefore must see plaintext to relay it.
          await whatsapp.sendMessageTo(from, recipientPhone, text);
        } catch (e) { console.error(`[whatsapp:${from}] failed to relay outgoing message:`, e.message); }
      }
    } catch (e) {
      console.error("[message] send failed:", e);
      ack && ack({ ok: false, error: "message could not be stored" });
    }
  });

  socket.on("group:message:send", async ({ groupId, iv, ciphertext }, ack) => {
    try {
      const from = socket.data.username;
      if (!from || !mongoose.isValidObjectId(groupId) || !iv || !ciphertext) return ack && ack({ ok: false, error: "invalid message" });
      const group = await Group.findOne({ _id: groupId, members: from }).select("_id members").lean();
      if (!group) return ack && ack({ ok: false, error: "not a group member" });
      const conversationId = `group:${groupId}`;
      const doc = await Message.create({ conversationId, from, to: String(groupId), iv, ciphertext });
      if (await userHasShortRetention(from)) await pruneConversation(conversationId);
      const payload = { id: doc._id, from, groupId: String(groupId), iv, ciphertext, ts: doc.createdAt.getTime() };
      io.to(`group:${groupId}`).emit("group:message:new", payload);
      ack && ack({ ok: true });
    } catch (e) {
      console.error("[group] send failed:", e);
      ack && ack({ ok: false, error: "group message could not be stored" });
    }
  });

  socket.on("disconnect", () => {
    const username = socket.data.username;
    if (!username || !socket.data.presenceRegistered) return;
    const next = Math.max(0, (onlineCounts.get(username) || 1) - 1);
    if (next === 0) {
      onlineCounts.delete(username);
      const lastSeenAt = new Date();
      User.updateOne({ username }, { $set: { lastSeenAt } }).catch(() => {});
      io.emit("presence:update", { username, online: false, lastSeenAt: lastSeenAt.getTime() });
    } else {
      onlineCounts.set(username, next);
      io.emit("presence:update", { username, online: true, lastSeenAt: null });
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
