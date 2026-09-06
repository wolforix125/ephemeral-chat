/**
 * Optional WhatsApp bridge, built on Baileys (@whiskeysockets/baileys).
 *
 * IMPORTANT - read this before turning it on:
 *   - Baileys is an unofficial, reverse-engineered client for WhatsApp Web.
 *     It is not sanctioned by WhatsApp/Meta. Automating a personal WhatsApp
 *     account this way is against WhatsApp's Terms of Service, and accounts
 *     used this way have been rate-limited or banned. Use a spare/test
 *     number, not your main one, and treat this as a hobby-project bridge,
 *     not something to depend on.
 *   - The compliant alternative is Meta's official WhatsApp Business
 *     Platform (Cloud API), which has a free tier for testing but requires
 *     a Meta Business/App review process. This file does NOT implement
 *     that - it implements the Baileys route you asked for, because it
 *     needs no approval and works with a normal phone number.
 *   - Once a message is bridged to WhatsApp, it is no longer end-to-end
 *     encrypted the way two in-app users are. The server has to hold the
 *     private key for the "whatsapp" bridge identity so it can decrypt
 *     what's sent to it and relay plaintext to WhatsApp (and re-encrypt
 *     what comes back). That's disclosed in the UI - the bridge is a
 *     real, server-side participant, not a silent observer.
 *
 * Set ENABLE_WHATSAPP=true and WHATSAPP_BRIDGE_TARGET=<phone in E.164,
 * e.g. 15551234567> in your .env to use it.
 */

const path = require("path");
const fs = require("fs");
const qrcode = require("qrcode");
const qrcodeTerminal = require("qrcode-terminal");
const pino = require("pino");

let sock = null;
let latestQrDataUrl = null;
let connectionState = "not_started"; // not_started | connecting | qr | open | closed
let onIncomingMessage = null; // (text) => void
let bridgeTarget = null; // phone number, digits only, no +

const AUTH_DIR = path.join(__dirname, "data", "whatsapp-auth");

async function initWhatsApp({ target, onMessage }) {
  bridgeTarget = String(target || "").replace(/[^\d]/g, "");
  onIncomingMessage = onMessage;

  if (!bridgeTarget) {
    console.warn("[whatsapp] ENABLE_WHATSAPP is true but WHATSAPP_BRIDGE_TARGET is not set - skipping bridge startup.");
    return;
  }

  fs.mkdirSync(AUTH_DIR, { recursive: true });

  // Baileys is loaded lazily so the rest of the server works fine even if
  // this package is missing or the bridge is disabled.
  const baileys = require("@whiskeysockets/baileys");
  const makeWASocket = baileys.default;
  const { useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = baileys;

  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version } = await fetchLatestBaileysVersion();

  connectionState = "connecting";
  sock = makeWASocket({
    version,
    auth: state,
    logger: pino({ level: "warn" }),
    printQRInTerminal: false
  });

  sock.ev.on("creds.update", saveCreds);

  sock.ev.on("connection.update", async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      connectionState = "qr";
      latestQrDataUrl = await qrcode.toDataURL(qr);
      console.log("\n[whatsapp] Scan this QR code with WhatsApp > Linked devices (or open /api/whatsapp/qr in a browser):\n");
      qrcodeTerminal.generate(qr, { small: true });
    }

    if (connection === "open") {
      connectionState = "open";
      latestQrDataUrl = null;
      console.log("[whatsapp] Linked and connected.");
    }

    if (connection === "close") {
      connectionState = "closed";
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      const loggedOut = statusCode === DisconnectReason.loggedOut;
      console.log(`[whatsapp] Connection closed (loggedOut=${loggedOut}).`);
      if (!loggedOut) {
        // transient disconnect - try again
        setTimeout(() => initWhatsApp({ target: bridgeTarget, onMessage: onIncomingMessage }), 4000);
      } else {
        console.log("[whatsapp] Logged out. Delete server/data/whatsapp-auth and restart to re-link.");
      }
    }
  });

  sock.ev.on("messages.upsert", async ({ messages, type }) => {
    if (type !== "notify") return;
    for (const m of messages) {
      if (m.key.fromMe) continue;
      const senderJid = m.key.remoteJid || "";
      const senderNumber = senderJid.split("@")[0];
      if (senderNumber !== bridgeTarget) continue; // only relay the configured contact

      const text =
        m.message?.conversation ||
        m.message?.extendedTextMessage?.text ||
        m.message?.imageMessage?.caption ||
        null;
      if (text && onIncomingMessage) {
        onIncomingMessage(text);
      }
    }
  });
}

async function sendWhatsAppMessage(text) {
  if (!sock || connectionState !== "open") {
    throw new Error("WhatsApp bridge is not connected yet. Check /api/whatsapp/status.");
  }
  const jid = `${bridgeTarget}@s.whatsapp.net`;
  await sock.sendMessage(jid, { text });
}

function getStatus() {
  return { state: connectionState, target: bridgeTarget, hasQr: !!latestQrDataUrl };
}

function getQrDataUrl() {
  return latestQrDataUrl;
}

module.exports = { initWhatsApp, sendWhatsAppMessage, getStatus, getQrDataUrl };
