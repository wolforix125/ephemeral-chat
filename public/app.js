(function () {
  "use strict";

  const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
  const IDENTITY_KEY = "ephemeral:identity";
  const CONTACTS_KEY = "ephemeral:contacts";

  let me = null; // { username, privateKey, publicKey (CryptoKey), publicJwk }
  let socket = null;
  let sharedKeyCache = {};
  let peerPubJwkCache = {};
  let currentPeer = null;

  const $ = (id) => document.getElementById(id);

  function b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function unb64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer; }
  function initials(name) { return (name || "?").slice(0, 2).toUpperCase(); }
  function escapeHtml(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
  function fmtClock(ts) { return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  function timeLeftLabel(ts) {
    const remain = (ts + THREE_DAYS_MS) - Date.now();
    if (remain <= 0) return "expired";
    const h = Math.floor(remain / 3600000);
    const d = Math.floor(h / 24);
    const hh = h % 24;
    if (d > 0) return `${d}d ${hh}h left`;
    const m = Math.floor((remain % 3600000) / 60000);
    if (h > 0) return `${h}h ${m}m left`;
    return `${m}m left`;
  }

  // ---------- Crypto (Web Crypto API - identical scheme to the server) ----------
  async function generateIdentity(username) {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { username, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, publicJwk, privateJwk };
  }
  async function importPrivate(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]); }
  async function importPublic(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []); }

  async function getSharedKey(peerUsername) {
    if (sharedKeyCache[peerUsername]) return sharedKeyCache[peerUsername];
    const resp = await fetch(`/api/users/${encodeURIComponent(peerUsername)}`);
    if (!resp.ok) throw new Error("no-such-user");
    const data = await resp.json();
    peerPubJwkCache[peerUsername] = data.publicKey;
    const peerPublicKey = await importPublic(data.publicKey);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPublicKey }, me.privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
    sharedKeyCache[peerUsername] = aesKey;
    return aesKey;
  }

  async function encryptFor(peerUsername, plaintext) {
    const key = await getSharedKey(peerUsername);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
    return { iv: b64(iv), ciphertext: b64(ct) };
  }

  async function decryptFrom(peerUsername, ivB64, ctB64) {
    try {
      const key = await getSharedKey(peerUsername);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(unb64(ivB64)) }, key, unb64(ctB64));
      return new TextDecoder().decode(pt);
    } catch (e) {
      return "⚠ could not decrypt this message";
    }
  }

  async function fingerprintFor(peerUsername) {
    const peerJwk = peerPubJwkCache[peerUsername];
    if (!peerJwk) return "";
    const combined = [me.publicJwk.x + me.publicJwk.y, peerJwk.x + peerJwk.y].sort().join("|");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(combined));
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    return hex.slice(0, 20).match(/.{1,4}/g).join(" ");
  }

  // ---------- Local (per-device) state ----------
  function loadContacts() { try { return JSON.parse(localStorage.getItem(CONTACTS_KEY)) || []; } catch (e) { return []; } }
  function saveContacts(list) { localStorage.setItem(CONTACTS_KEY, JSON.stringify(list)); }
  function addContact(username) {
    const list = loadContacts();
    if (!list.includes(username)) { list.unshift(username); saveContacts(list); }
    return list;
  }

  // ---------- Setup flow ----------
  function tryAutoLogin() {
    const raw = localStorage.getItem(IDENTITY_KEY);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  async function handleSetup() {
    const input = $("username-input");
    const btn = $("setup-btn");
    const msg = $("setup-msg");
    const username = input.value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    if (!username) { msg.textContent = "Pick a handle using letters, numbers, _ . -"; return; }

    btn.disabled = true;
    msg.textContent = "Generating your key pair…";

    const identity = await generateIdentity(username);
    const resp = await fetch("/api/register", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, publicKey: identity.publicJwk })
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      msg.textContent = err.error === "handle already taken"
        ? "That handle is taken. Pick another one, or if it's yours, open this app on the original device."
        : (err.error || "Something went wrong. Try again.");
      btn.disabled = false;
      return;
    }

    localStorage.setItem(IDENTITY_KEY, JSON.stringify({ username, privateKey: identity.privateJwk, publicKey: identity.publicJwk }));
    me = { username, privateKey: identity.privateKey, publicKey: identity.publicKey, publicJwk: identity.publicJwk };
    enterApp();
  }

  function resetIdentity() {
    if (!confirm("Forget your key on this device? You'll lose access to past messages here and can register a new handle.")) return;
    localStorage.removeItem(IDENTITY_KEY);
    localStorage.removeItem(CONTACTS_KEY);
    location.reload();
  }

  // ---------- Rendering ----------
  function enterApp() {
    $("setup-screen").style.display = "none";
    $("app-screen").style.display = "block";
    $("me-name").textContent = me.username;
    $("me-avatar").textContent = initials(me.username);
    renderContacts();
    connectSocket();
    checkBridge();
  }

  function connectSocket() {
    socket = io();
    socket.on("connect", () => {
      socket.emit("identify", me.username);
      $("conn-status").textContent = "● connected";
      $("conn-status").classList.add("online");
    });
    socket.on("disconnect", () => {
      $("conn-status").textContent = "○ reconnecting…";
      $("conn-status").classList.remove("online");
    });
    socket.on("message:new", async (m) => {
      // Only messages in the currently-open conversation get live-rendered;
      // others just update the contact list.
      const other = m.from === me.username ? m.to : m.from;
      if (other === currentPeer) {
        await appendMessage(m);
      }
      addContact(other);
      renderContacts();
    });
  }

  async function checkBridge() {
    try {
      const resp = await fetch("/api/whatsapp/status");
      const data = await resp.json();
      const hint = $("bridge-hint");
      if (data.enabled) {
        hint.classList.remove("hidden");
        hint.innerHTML = data.state === "open"
          ? `<b>WhatsApp bridge is linked.</b> Message the handle "whatsapp" and it relays to your phone.`
          : `<b>WhatsApp bridge not linked yet.</b> Check the server logs (or /api/whatsapp/qr) for a QR code.`;
        hint.onclick = () => openChat("whatsapp");
      }
    } catch (e) { /* bridge status is optional, ignore failures */ }
  }

  function renderContacts() {
    const list = loadContacts();
    const box = $("contacts");
    if (list.length === 0) {
      box.innerHTML = `<div id="contacts-empty">No conversations yet. Enter someone's handle above — they need to have registered that handle already.</div>`;
      return;
    }
    box.innerHTML = "";
    list.forEach(username => {
      const el = document.createElement("div");
      el.className = "contact" + (currentPeer === username ? " active" : "");
      el.innerHTML = `
        <div class="avatar">${initials(username)}</div>
        <div style="min-width:0;">
          <div class="contact-name">${escapeHtml(username)}</div>
          <div class="contact-meta">end-to-end encrypted</div>
        </div>`;
      el.onclick = () => openChat(username);
      box.appendChild(el);
    });
  }

  async function openChat(peer) {
    if (peer === me.username) return;
    try {
      await getSharedKey(peer);
    } catch (e) {
      alert(`No one with the handle "${peer}" has registered yet.`);
      return;
    }
    currentPeer = peer;
    addContact(peer);
    renderContacts();

    $("chat-empty").style.display = "none";
    $("chat-active").style.display = "flex";
    $("peer-avatar").textContent = initials(peer);
    $("chat-peer-name").textContent = peer;
    $("fingerprint").textContent = "verifying…";
    fingerprintFor(peer).then(fp => { $("fingerprint").textContent = fp; });

    const resp = await fetch(`/api/messages/${encodeURIComponent(peer)}?me=${encodeURIComponent(me.username)}`);
    const msgs = resp.ok ? await resp.json() : [];
    const box = $("messages");
    box.innerHTML = "";
    for (const m of msgs) await appendMessage(m, { scroll: false });
    box.scrollTop = box.scrollHeight;
  }

  async function appendMessage(m, opts = {}) {
    if (!currentPeer) return;
    const other = m.from === me.username ? m.to : m.from;
    if (other !== currentPeer) return;
    if ((Date.now() - m.ts) >= THREE_DAYS_MS) return; // already expired, don't render

    const box = $("messages");
    const empty = document.getElementById("no-msgs-placeholder");
    if (empty) empty.remove();

    const outgoing = m.from === me.username;
    const text = await decryptFrom(currentPeer, m.iv, m.ciphertext);
    const row = document.createElement("div");
    row.className = "msg-row " + (outgoing ? "out" : "in");
    row.innerHTML = `<div class="bubble">${escapeHtml(text)}<div class="bubble-meta"><span>${fmtClock(m.ts)}</span><span>·</span><span>${timeLeftLabel(m.ts)}</span></div></div>`;
    box.appendChild(row);
    if (opts.scroll !== false) box.scrollTop = box.scrollHeight;
  }

  async function sendMessage() {
    const input = $("compose-input");
    const text = input.value.trim();
    if (!text || !currentPeer) return;
    input.value = "";
    try {
      const { iv, ciphertext } = await encryptFor(currentPeer, text);
      socket.emit("message:send", { to: currentPeer, iv, ciphertext }, (ack) => {
        if (!ack || !ack.ok) alert("Message failed to send: " + (ack && ack.error));
      });
    } catch (e) {
      alert("Couldn't send — " + e.message);
    }
  }

  // ---------- Wire up ----------
  $("setup-btn").addEventListener("click", handleSetup);
  $("username-input").addEventListener("keydown", e => { if (e.key === "Enter") handleSetup(); });
  $("reset-btn").addEventListener("click", resetIdentity);
  $("new-chat-btn").addEventListener("click", () => {
    const v = $("new-chat-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    if (v) { openChat(v); $("new-chat-input").value = ""; }
  });
  $("new-chat-input").addEventListener("keydown", e => { if (e.key === "Enter") $("new-chat-btn").click(); });
  $("send-btn").addEventListener("click", sendMessage);
  $("compose-input").addEventListener("keydown", e => { if (e.key === "Enter") sendMessage(); });

  (async function init() {
    const stored = tryAutoLogin();
    if (!stored) return;
    const privateKey = await importPrivate(stored.privateKey);
    const publicKey = await importPublic(stored.publicKey);
    me = { username: stored.username, privateKey, publicKey, publicJwk: stored.publicKey };
    enterApp();
  })();

})();
