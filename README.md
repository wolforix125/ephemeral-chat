# Ephemeral — end-to-end encrypted chat, deployable for free

A real, hosted version of the encrypted chat app: Node/Express + Socket.io backend,
MongoDB for storage (with a native 3-day TTL so messages truly delete themselves),
and an optional bridge to your personal WhatsApp via Baileys.

**Encryption model:** every browser generates an ECDH (P-256) key pair. Private
keys never leave the browser (stored in `localStorage`). The server only ever
stores public keys and opaque AES-GCM ciphertext — it cannot read your messages.
The one exception is the optional WhatsApp bridge, explained below, which is a
real participant the server operates on your behalf, not a silent reader of
other people's chats.

## What you need (all free)

1. A [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register) account — free M0 cluster, no credit card required.
2. A [Render](https://render.com) account — free Web Service tier.
3. A [GitHub](https://github.com) account, to hold the repo Render deploys from.
4. (Optional) A spare phone number with WhatsApp, if you want the bridge.

## 1. Get a database

1. Create a free M0 cluster in Atlas.
2. Under **Database Access**, add a user with a password.
3. Under **Network Access**, add `0.0.0.0/0` (allow from anywhere) — Render's free tier has no fixed IP, so this is required unless you upgrade.
4. Click **Connect → Drivers**, copy the connection string. It looks like:
   `mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/ephemeral-chat`
   Add a database name at the end (e.g. `/ephemeral-chat`) if it isn't there already.

## 2. Push this project to GitHub

```bash
cd ephemeral-chat
git init
git add .
git commit -m "Ephemeral chat"
git branch -M main
git remote add origin https://github.com/<you>/ephemeral-chat.git
git push -u origin main
```

## 3. Deploy to Render

**Option A — Blueprint (fastest):** this repo includes `render.yaml`. In Render, click
**New → Blueprint**, point it at your repo, and Render reads the file and creates the
service for you. You'll be prompted for `MONGODB_URI`.

**Option B — Manual:**
1. **New → Web Service**, connect your repo.
2. Root directory: `server`
3. Build command: `npm install`
4. Start command: `node index.js`
5. Instance type: **Free**
6. Add environment variables (see `server/.env.example`):
   - `MONGODB_URI` — from step 1
   - `ENABLE_WHATSAPP` — `false` to start
7. Deploy. Render gives you a URL like `https://ephemeral-chat.onrender.com` — that's your live app.

That's it — open the URL, pick a handle, and share it with someone else so they can
register a handle too and you can message each other.

### Free-tier reality check
- Render's free web services **spin down after ~15 minutes idle** and take
  20–50 seconds to wake back up on the next request. Fine for a personal project,
  not for something you need always-on without a paid instance.
- MongoDB Atlas M0 is free forever but capped at 512MB storage — plenty for
  ciphertext that auto-deletes after 3 days.
- There's no password/login system here — anyone who knows a handle exists
  can message it, same trust model as the original demo. Don't use this for
  anything sensitive without adding real authentication first.

## 4. (Optional) Turn on the WhatsApp bridge

This uses [Baileys](https://github.com/WhiskeySockets/Baileys), an **unofficial**,
reverse-engineered WhatsApp Web client — not Meta's official API. Read this before
enabling it:

- Automating a personal WhatsApp account this way is against WhatsApp's Terms
  of Service. Accounts used this way have been rate-limited or banned. **Use a
  spare number you can afford to lose, not your primary one.**
- The compliant alternative is Meta's official **WhatsApp Business Platform
  (Cloud API)**, which has a free testing tier but requires a Meta Business
  account and app review. That's a different (larger) integration — ask if
  you'd like that route built instead.
- Once bridged, messages to/from WhatsApp are decrypted on the server so they
  can be relayed as plaintext WhatsApp messages. That leg is **not** end-to-end
  encrypted the way two in-app users are — the server necessarily holds the
  bridge's private key, the same way any bot/bridge participant in a chat can
  read what's sent directly to it. The app is upfront about this rather than
  hiding it.

To enable it:

1. In Render's environment variables, set:
   - `ENABLE_WHATSAPP=true`
   - `WHATSAPP_BRIDGE_TARGET=<phone in E.164 digits, no +>` — e.g. `15551234567`, the number you'll text with
   - `WHATSAPP_APP_USERNAME=<your in-app handle>` — where incoming WhatsApp messages land
2. Redeploy. Open the **Logs** tab in Render — a QR code prints there (or fetch
   `https://your-app.onrender.com/api/whatsapp/qr` in a browser for an image version).
3. On your phone: WhatsApp → **Settings → Linked devices → Link a device**, scan the QR.
4. Once linked, message the in-app handle **`whatsapp`** from your account — it
   relays to your phone over WhatsApp, and replies from that number show up
   back in the app as messages from `whatsapp`.

**Persistence caveat:** Baileys' login session is written to
`server/data/whatsapp-auth/`. Render's free tier disk is not guaranteed to
survive every redeploy, so you may need to re-scan the QR after deploying
changes. If that gets annoying, the fix is to move that auth state into
MongoDB too (same pattern already used for the bridge's encryption keypair
in `server/index.js` — ask if you'd like that wired up) or move to a paid
Render instance with a persistent disk.

## Local development

```bash
cd server
cp .env.example .env   # fill in MONGODB_URI
npm install
npm run dev
```

Then open `http://localhost:3000`.

## Project layout

```
ephemeral-chat/
  server/
    index.js         Express + Socket.io + Mongo, REST + realtime relay
    whatsapp.js       Baileys bridge (optional)
    models/           User (handles + public keys), Message (TTL-indexed)
    .env.example
  public/
    index.html        UI shell
    styles.css
    app.js             All client crypto + socket/rest logic (private keys live here, in localStorage)
  render.yaml           Render Blueprint
```
