const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("./models/User");

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error("Missing SESSION_SECRET in your environment (any long random string). See .env.example.");
  process.exit(1);
}

function normalizePhone(p) { return String(p || "").replace(/[^\d]/g, ""); }
function signSession(payload) { return jwt.sign(payload, SESSION_SECRET, { expiresIn: "90d" }); }
function verifySession(token) { try { return jwt.verify(token, SESSION_SECRET); } catch { return null; } }
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const payload = token && verifySession(token);
  if (!payload?.handle) return res.status(401).json({ error: "sign in required" });
  req.auth = payload;
  next();
}

async function registerAuthRoutes(app) {
  // Account creation is deliberately handle-first. No phone number is required.
  app.post("/api/auth/create", async (req, res) => {
    const { handle, publicKey, encryptedPrivateKey, iv, salt } = req.body || {};
    if (!handle || !publicKey || !encryptedPrivateKey || !iv || !salt) return res.status(400).json({ error: "missing fields" });
    const clean = String(handle).toLowerCase().trim().replace(/[^a-z0-9_.-]/g, "");
    if (!clean || clean.length > 24) return res.status(400).json({ error: "invalid handle" });
    if (clean.startsWith("wa-")) return res.status(409).json({ error: 'handles starting with "wa-" are reserved' });
    if (await User.findOne({ username: clean })) return res.status(409).json({ error: "handle already taken" });
    const account = await User.create({ username: clean, publicKey, encryptedPrivateKey, ivBackup: iv, saltBackup: salt });
    const sessionToken = signSession({ handle: account.username });
    res.json({ ok: true, sessionToken, handle: account.username });
  });

  // New device login: handle + recovery passphrase unlocks the encrypted key backup locally.
  // The server never receives the passphrase.
  app.get("/api/auth/account/:handle", async (req, res) => {
    const handle = String(req.params.handle).toLowerCase().trim().replace(/[^a-z0-9_.-]/g, "");
    const account = await User.findOne({ username: handle }).select("username publicKey encryptedPrivateKey ivBackup saltBackup").lean();
    if (!account) return res.status(404).json({ error: "handle not found" });
    res.json({ handle: account.username, publicKey: account.publicKey, encryptedPrivateKey: account.encryptedPrivateKey, iv: account.ivBackup, salt: account.saltBackup });
  });

  app.post("/api/auth/login", async (req, res) => {
    const handle = String(req.body?.handle || "").toLowerCase().trim().replace(/[^a-z0-9_.-]/g, "");
    if (!handle) return res.status(400).json({ error: "enter your handle" });
    const account = await User.findOne({ username: handle }).select("username publicKey encryptedPrivateKey ivBackup saltBackup").lean();
    if (!account) return res.status(404).json({ error: "handle not found" });
    res.json({ ok: true, handle: account.username, publicKey: account.publicKey, encryptedPrivateKey: account.encryptedPrivateKey, iv: account.ivBackup, salt: account.salt });
  });
}

module.exports = { registerAuthRoutes, requireAuth, verifySession, normalizePhone, signSession };
