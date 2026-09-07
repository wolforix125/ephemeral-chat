/**
 * WhatsApp integration, built on Baileys (@whiskeysockets/baileys) - an
 * unofficial, reverse-engineered WhatsApp Web client, not Meta's official
 * API. Two kinds of sessions live here:
 *
 *  1. The "verifier" - one shared bot account (linked once by whoever
 *     deploys this, via /api/admin/verifier/qr) that sends account
 *     verification codes over WhatsApp instead of paid SMS. Everyone's
 *     phone-based login depends on this bot staying linked.
 *
 *  2. Per-user "mirror" sessions - each app user can link their own
 *     WhatsApp account. Once linked, ANY inbound message from ANY contact
 *     is mirrored into one merged thread in the app - there's no
 *     allow-list. That's a deliberate, disclosed trade-off: convenient,
 *     but it means your linked number is an open door in this app the
 *     moment it's linked. The UI keeps a persistent warning about this
 *     wherever that thread is shown.
 *
 * READ BEFORE LINKING ANYTHING:
 *   - Automating a personal WhatsApp account this way is against
 *     WhatsApp's Terms of Service. Numbers used this way have been
 *     rate-limited or banned - use a number you can afford to lose,
 *     never your only number, and definitely not for the verifier bot
 *     that every user's login depends on.
 *   - The compliant alternative is Meta's official WhatsApp Business
 *     Platform (Cloud API); ask if you'd like that built instead.
 *   - The server necessarily sees plaintext for anything relayed to/from
 *     WhatsApp - it has to, to speak WhatsApp's protocol. See index.js
 *     for exactly how that's scoped.
 */

const qrcode = require("qrcode");
const qrcodeTerminal = require("qrcode-terminal");
const pino = require("pino");
const { useMongoAuthState, clearMongoAuthState } = require("./whatsappAuthMongo");

const VERIFIER_KEY = "__verifier__";

const sessions = new Map(); // key -> { sock, connectionState, latestQrDataUrl, mode, onMessage }

async function startSession(key, mode, onMessage) {
  const existing = sessions.get(key);
  if (existing && ["connecting", "qr", "open"].includes(existing.connectionState)) {
    return existing;
  }

  const entry = { sock: null, connectionState: "connecting", latestQrDataUrl: null, mode, onMessage, ownNumber: null };
  sessions.set(key, entry);

  const baileys = require("@whiskeysockets/baileys");
  const makeWASocket = baileys.default;
  const { DisconnectReason, fetchLatestBaileysVersion } = baileys;

  const { state, saveCreds } = await useMongoAuthState(key);
  const { version } = await fetchLatestBaileysVersion();

  const sock = makeWASocket({
    version,
    auth: state,
    logger: pino({ level: "warn" }),
    printQRInTerminal: false
  });
  entry.sock = sock;

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      entry.connectionState = "qr";
      entry.latestQrDataUrl = await qrcode.toDataURL(qr);
      console.log(`\n[whatsapp:${key}] Scan this QR with WhatsApp > Linked devices:\n`);
      qrcodeTerminal.generate(qr, { small: true });
    }
    if (connection === "open") {
      entry.connectionState = "open";
      entry.latestQrDataUrl = null;
      entry.ownNumber = String(sock.user?.id || "").split(":")[0].replace(/[^0-9]/g, "") || null;
      console.log(`[whatsapp:${key}] Linked and connected.`);
    }
    if (connection === "close") {
      entry.connectionState = "closed";
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const loggedOut = statusCode === DisconnectReason.loggedOut;
      console.log(`[whatsapp:${key}] Connection closed (loggedOut=${loggedOut}).`);
      if (!loggedOut) {
        setTimeout(() => startSession(key, mode, onMessage), 4000);
      } else {
        await clearMongoAuthState(key);
        sessions.delete(key);
      }
    }
  });

  if (mode === "mirror") {
    sock.ev.on("messages.upsert", async ({ messages, type }) => {
      if (type !== "notify") return;
      for (const m of messages) {
        if (m.key.fromMe) continue;
        const senderNumber = (m.key.remoteJid || "").split("@")[0];
        if (!senderNumber || senderNumber.includes("@g.us")) continue; // skip groups/system
        const text =
          m.message?.conversation ||
          m.message?.extendedTextMessage?.text ||
          m.message?.imageMessage?.caption ||
          null;
        if (text && onMessage) onMessage(senderNumber, m.pushName || senderNumber, text);
      }
    });
  }

  return entry;
}

async function startVerifier() {
  return startSession(VERIFIER_KEY, "verify-only", null);
}

async function sendMessageTo(sessionKey, toNumber, text) {
  const entry = sessions.get(sessionKey);
  if (!entry || entry.connectionState !== "open") {
    throw new Error(`WhatsApp session "${sessionKey}" is not connected.`);
  }
  await entry.sock.sendMessage(`${toNumber}@s.whatsapp.net`, { text });
}

function getStatus(key) {
  const entry = sessions.get(key);
  if (!entry) return { state: "not_started" };
  return { state: entry.connectionState, ownNumber: entry.ownNumber };
}

function getQrDataUrl(key) {
  const entry = sessions.get(key);
  return entry ? entry.latestQrDataUrl : null;
}

module.exports = { startSession, startVerifier, sendMessageTo, getStatus, getQrDataUrl, VERIFIER_KEY };
