const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("./models/User");
const Otp = require("./models/Otp");
const whatsapp = require("./whatsapp");
const LoginRequest = require("./models/LoginRequest");

const SESSION_SECRET = process.env.SESSION_SECRET;
const DEV_MODE = String(process.env.DEV_MODE || "false") === "true";
const OTP_TTL_LABEL = "10 minutes";

if (!SESSION_SECRET) {
  console.error("Missing SESSION_SECRET in your environment (any long random string). See .env.example.");
  process.exit(1);
}

function normalizePhone(p) {
  return String(p || "").replace(/[^\d]/g, "");
}
function hashCode(code, phone) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(`${phone}:${code}`).digest("hex");
}
function signSession(payload, expiresIn = "90d") {
  return jwt.sign(payload, SESSION_SECRET, { expiresIn });
}
function verifySession(token) {
  try { return jwt.verify(token, SESSION_SECRET); } catch (e) { return null; }
}

// Express middleware: requires a valid session, attaches req.auth = {phone, handle}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const payload = token && verifySession(token);
  if (!payload) return res.status(401).json({ error: "sign in required" });
  req.auth = payload;
  next();
}


function hashApprovalCode(code, requestId) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(`${requestId}:${code}`).digest("hex");
}
function requestDeviceInfo(req) {
  const ua = String(req.get("user-agent") || "");
  const low = ua.toLowerCase();
  let deviceName = /ipad/.test(low) ? "iPad" : /iphone/.test(low) ? "iPhone" : /android/.test(low) ? "Android device" : /macintosh/.test(low) ? "Mac" : /windows/.test(low) ? "Windows PC" : /linux/.test(low) ? "Linux PC" : "Unknown device";
  let browser = /edg\//.test(low) ? "Microsoft Edge" : /chrome\//.test(low) ? "Chrome" : /firefox\//.test(low) ? "Firefox" : /safari\//.test(low) ? "Safari" : "Unknown browser";
  let os = /windows/.test(low) ? "Windows" : /iphone|ipad/.test(low) ? "iOS/iPadOS" : /android/.test(low) ? "Android" : /mac os x/.test(low) ? "macOS" : /linux/.test(low) ? "Linux" : "Unknown OS";
  return { deviceName, browser, os, ip: req.ip || req.socket?.remoteAddress || "unknown", userAgent: ua };
}

function registerAuthRoutes(app, hooks = {}) {

  app.get("/api/auth/pending-requests", requireAuth, async (req, res) => {
    const requests = await LoginRequest.find({ targetHandle: req.auth.handle, status: "pending" }).sort({ createdAt: -1 }).limit(20).lean();
    res.json(requests.map(r => ({
      requestId: r.requestId, approvalCode: r.approvalCode, phone: r.phone.replace(/\d(?=\d{4})/g, "•"),
      deviceName: r.deviceName, browser: r.browser, os: r.os, ip: r.ip, createdAt: r.createdAt.getTime()
    })));
  });

  // A handle can also be used to request access to an already-created account.
  // The existing account's trusted devices must approve the request.
  app.post("/api/auth/request-handle-access", async (req, res) => {
    const handle = String(req.body?.handle || "").toLowerCase().trim().replace(/[^a-z0-9_.-]/g, "");
    const phone = normalizePhone(req.body?.phone);
    if (!handle || !phone) return res.status(400).json({ error: "handle and phone are required" });
    const account = await User.findOne({ username: handle });
    if (!account || account.isBridge) return res.status(404).json({ error: "handle not found" });

    const pending = await LoginRequest.findOne({ targetHandle: handle, phone, status: "pending" });
    if (pending) {
      const requestToken = signSession({ purpose: "handle-request", requestId: pending.requestId, phone }, "10m");
      return res.json({ ok: true, status: "pending", requestId: pending.requestId, requestToken, approvalCode: pending.approvalCode, device: { deviceName: pending.deviceName, browser: pending.browser, os: pending.os, ip: pending.ip } });
    }

    const requestId = crypto.randomBytes(18).toString("hex");
    const approvalCode = String(Math.floor(100000 + Math.random() * 900000));
    const info = requestDeviceInfo(req);
    await LoginRequest.create({
      requestId, targetHandle: handle, phone,
      approvalCodeHash: hashApprovalCode(approvalCode, requestId),
      approvalCode,
      ...info
    });
    const requestToken = signSession({ purpose: "handle-request", requestId, phone }, "10m");
    if (typeof hooks.onHandleRequest === "function") {
      hooks.onHandleRequest(handle, { requestId, approvalCode, phone, device: info });
    }
    res.json({ ok: true, status: "pending", requestId, requestToken, approvalCode, device: info });
  });

  app.get("/api/auth/handle-request/:requestId", async (req, res) => {
    const requestId = String(req.params.requestId || "");
    const requestPayload = verifySession(req.query.token || "");
    if (!requestPayload || requestPayload.purpose !== "handle-request" || requestPayload.requestId !== requestId) return res.status(401).json({ error: "invalid request token" });
    const request = await LoginRequest.findOne({ requestId, phone: requestPayload.phone }).lean();
    if (!request) return res.status(404).json({ error: "request expired or not found" });
    if (request.status === "approved") {
      const account = await User.findOne({ username: request.targetHandle });
      if (!account) return res.status(404).json({ error: "account no longer exists" });
      return res.json({
        ok: true, status: "approved", handle: account.username, publicKey: account.publicKey,
        encryptedPrivateKey: account.encryptedPrivateKey, iv: account.ivBackup, salt: account.saltBackup,
        sessionToken: signSession({ phone: request.phone, handle: account.username })
      });
    }
    res.json({ ok: true, status: request.status, handle: request.targetHandle });
  });

  app.post("/api/auth/handle-request/:requestId/approve", requireAuth, async (req, res) => {
    const requestId = String(req.params.requestId || "");
    const request = await LoginRequest.findOne({ requestId, targetHandle: req.auth.handle, status: "pending" });
    if (!request) return res.status(404).json({ error: "request is no longer pending" });
    request.status = "approved";
    await request.save();
    res.json({ ok: true });
  });

  app.post("/api/auth/handle-request/:requestId/decline", requireAuth, async (req, res) => {
    const requestId = String(req.params.requestId || "");
    const request = await LoginRequest.findOne({ requestId, targetHandle: req.auth.handle, status: "pending" });
    if (!request) return res.status(404).json({ error: "request is no longer pending" });
    request.status = "declined";
    await request.save();
    res.json({ ok: true });
  });

  app.post("/api/auth/request-code", async (req, res) => {
    const phone = normalizePhone(req.body?.phone);
    if (!phone || phone.length < 6) return res.status(400).json({ error: "enter a valid phone number with country code" });

    const recent = await Otp.findOne({ phone });
    if (recent && Date.now() - recent.createdAt.getTime() < 30 * 1000) {
      return res.status(429).json({ error: "please wait a bit before requesting another code" });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    await Otp.findOneAndUpdate(
      { phone },
      { phone, codeHash: hashCode(code, phone), attempts: 0, createdAt: new Date() },
      { upsert: true }
    );

    const verifierStatus = whatsapp.getStatus(whatsapp.VERIFIER_KEY);
    if (verifierStatus.state === "open") {
      try {
        await whatsapp.sendMessageTo(whatsapp.VERIFIER_KEY, phone, `Your Ephemeral verification code is ${code}. It expires in ${OTP_TTL_LABEL}. Didn't request this? Ignore it.`);
        return res.json({ ok: true, deliveredVia: "whatsapp" });
      } catch (e) {
        console.error("[auth] failed to send code via WhatsApp:", e.message);
      }
    }

    if (DEV_MODE) {
      console.log(`[auth][dev] verification code for ${phone}: ${code}`);
      return res.json({ ok: true, deliveredVia: "dev-console", devCode: code });
    }

    return res.status(503).json({ error: "the verification bot isn't linked yet - ask the admin to link it (see README), or run with DEV_MODE=true to test locally" });
  });

  app.post("/api/auth/verify", async (req, res) => {
    const phone = normalizePhone(req.body?.phone);
    const code = String(req.body?.code || "").trim();
    if (!phone || !code) return res.status(400).json({ error: "phone and code are required" });

    const otp = await Otp.findOne({ phone });
    if (!otp) return res.status(400).json({ error: "no code pending for this number - request a new one" });
    if (otp.attempts >= 5) return res.status(429).json({ error: "too many attempts - request a new code" });

    if (otp.codeHash !== hashCode(code, phone)) {
      otp.attempts += 1;
      await otp.save();
      return res.status(401).json({ error: "incorrect code" });
    }
    await Otp.deleteOne({ phone });

    const account = await User.findOne({ phone });
    if (account) {
      const sessionToken = signSession({ phone, handle: account.username });
      return res.json({
        ok: true, status: "existing", sessionToken,
        handle: account.username, publicKey: account.publicKey,
        encryptedPrivateKey: account.encryptedPrivateKey, iv: account.ivBackup, salt: account.saltBackup
      });
    }

    // New phone number - issue a short-purpose token that only /api/auth/create accepts.
    const createToken = signSession({ phone, purpose: "create" }, "10m");
    res.json({ ok: true, status: "new", createToken });
  });

  app.post("/api/auth/create", async (req, res) => {
    const { createToken, handle, publicKey, encryptedPrivateKey, iv, salt } = req.body || {};
    const payload = createToken && verifySession(createToken);
    if (!payload || payload.purpose !== "create") return res.status(401).json({ error: "verify your phone number again" });
    if (!handle || !publicKey || !encryptedPrivateKey || !iv || !salt) return res.status(400).json({ error: "missing fields" });

    const clean = String(handle).toLowerCase().trim().replace(/[^a-z0-9_.-]/g, "");
    if (!clean || clean.length > 24) return res.status(400).json({ error: "invalid handle" });
    if (clean.startsWith("wa-")) return res.status(409).json({ error: 'handles starting with "wa-" are reserved' });

    const takenHandle = await User.findOne({ username: clean });
    if (takenHandle) return res.status(409).json({ error: "handle already taken" });
    const takenPhone = await User.findOne({ phone: payload.phone });
    if (takenPhone) return res.status(409).json({ error: "an account for this phone number already exists" });

    await User.create({
      username: clean, phone: payload.phone, publicKey,
      encryptedPrivateKey, ivBackup: iv, saltBackup: salt
    });

    const sessionToken = signSession({ phone: payload.phone, handle: clean });
    res.json({ ok: true, sessionToken, handle: clean });
  });
}

module.exports = { registerAuthRoutes, requireAuth, verifySession, normalizePhone };
