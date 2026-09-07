(function () {
  "use strict";

  const THREE_DAYS_MS = 3 * 24 * 60 * 60 * 1000;
  const SESSION_KEY = "ephemeral:session";     // { sessionToken, handle, phone }
  const DEVICE_KEY_KEY = "ephemeral:devicekey"; // { privateKey JWK, publicKey JWK } - only once unlocked on this device
  const CONTACTS_KEY = "ephemeral:contacts";

  let me = null;            // { handle, phone, privateKey (CryptoKey), publicKey (CryptoKey), publicJwk, sessionToken }
  let socket = null;
  let sharedKeyCache = {};
  let peerPubJwkCache = {};
  let currentPeer = null;
  let currentGroupId = null;
  let myGroups = []; // [{id, name}]
  let groupKeyCache = {}; // groupId -> AES-GCM CryptoKey
  let peerWhatsappLinked = {}; // handle -> bool
  let pendingCreateToken = null; // set after OTP verify for brand-new phone numbers

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
  async function api(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (me && me.sessionToken) headers.Authorization = `Bearer ${me.sessionToken}`;
    const resp = await fetch(path, Object.assign({}, opts, { headers }));
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `request failed (${resp.status})`);
    return data;
  }

  // ---------- Key-pair crypto (identity) ----------
  async function generateIdentity() {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, publicJwk, privateJwk };
  }
  async function importPrivate(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]); }
  async function importPublic(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []); }

  // ---------- Passphrase-based key wrapping (for multi-device recovery) ----------
  async function deriveWrapKey(passphrase, saltBytes) {
    const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: 210000, hash: "SHA-256" },
      baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }
  async function wrapPrivateKey(privateJwk, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await deriveWrapKey(passphrase, salt);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, new TextEncoder().encode(JSON.stringify(privateJwk)));
    return { encryptedPrivateKey: b64(ct), iv: b64(iv), salt: b64(salt) };
  }
  async function unwrapPrivateKey(encryptedPrivateKeyB64, ivB64, saltB64, passphrase) {
    const wrapKey = await deriveWrapKey(passphrase, new Uint8Array(unb64(saltB64)));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(unb64(ivB64)) }, wrapKey, unb64(encryptedPrivateKeyB64));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  // ---------- Messaging crypto ----------
  async function getSharedKey(peerUsername) {
    if (sharedKeyCache[peerUsername]) return sharedKeyCache[peerUsername];
    const data = await api(`/api/users/${encodeURIComponent(peerUsername)}`);
    peerPubJwkCache[peerUsername] = data.publicKey;
    peerWhatsappLinked[peerUsername] = !!data.whatsappLinked;
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
    } catch (e) { return "⚠ could not decrypt this message"; }
  }
  async function fingerprintFor(peerUsername) {
    const peerJwk = peerPubJwkCache[peerUsername];
    if (!peerJwk) return "";
    const combined = [me.publicJwk.x + me.publicJwk.y, peerJwk.x + peerJwk.y].sort().join("|");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(combined));
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    return hex.slice(0, 20).match(/.{1,4}/g).join(" ");
  }

  // ---------- Group messaging crypto ----------
  // Group key is a plain AES-GCM key generated by the creator and wrapped
  // per-member using the SAME pairwise ECDH shared key already used for 1:1
  // chat (getSharedKey), so no new key-exchange mechanism is needed.
  async function encryptForGroup(groupId, plaintext) {
    const key = groupKeyCache[groupId];
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
    return { iv: b64(iv), ciphertext: b64(ct) };
  }
  async function decryptFromGroup(groupId, ivB64, ctB64) {
    try {
      const key = groupKeyCache[groupId];
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(unb64(ivB64)) }, key, unb64(ctB64));
      return new TextDecoder().decode(pt);
    } catch (e) { return "⚠ could not decrypt this message"; }
  }

  async function createGroup() {
    const name = prompt("Group name?");
    if (!name) return;
    const raw = prompt("Member handles, comma-separated (you're added automatically):");
    if (raw === null) return;
    const members = [...new Set(raw.split(",").map(s => s.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "")).filter(Boolean).concat(me.handle))];
    try {
      const groupKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const rawKey = await crypto.subtle.exportKey("raw", groupKey);
      const wrappedKeys = [];
      for (const m of members) {
        const shared = await getSharedKey(m);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, shared, rawKey);
        wrappedKeys.push({ username: m, iv: b64(iv), ciphertext: b64(ct) });
      }
      const data = await api("/api/groups", { method: "POST", body: JSON.stringify({ name, wrappedKeys }) });
      groupKeyCache[data.id] = groupKey;
      myGroups.unshift({ id: data.id, name: data.name });
      renderContacts();
      openGroup(data.id, data.name);
    } catch (e) { alert("Couldn't create group — " + e.message); }
  }

  async function loadGroups() {
    try {
      const groups = await api("/api/groups");
      for (const g of groups) {
        if (!groupKeyCache[g.id] && g.myWrappedKey) {
          try {
            const shared = await getSharedKey(g.owner);
            const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(unb64(g.myWrappedKey.iv)) }, shared, unb64(g.myWrappedKey.ciphertext));
            groupKeyCache[g.id] = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
          } catch (e) { console.error("couldn't unwrap group key for", g.id, e); }
        }
      }
      myGroups = groups.map(g => ({ id: g.id, name: g.name }));
      renderContacts();
    } catch (e) { /* optional */ }
  }

  async function openGroup(id, name) {
    currentPeer = null;
    currentGroupId = id;
    $("chat-empty").style.display = "none";
    $("chat-active").style.display = "flex";
    $("peer-avatar").textContent = initials(name);
    $("chat-peer-name").textContent = name;
    $("merged-inbox-warning").classList.add("hidden");
    $("fingerprint").textContent = "group chat";
    renderContacts();

    const msgs = await api(`/api/groups/${encodeURIComponent(id)}/messages`);
    const box = $("messages");
    box.innerHTML = "";
    for (const m of msgs) {
      const text = await decryptFromGroup(id, m.iv, m.ciphertext);
      const row = document.createElement("div");
      row.className = "msg-row " + (m.from === me.handle ? "out" : "in");
      row.innerHTML = `<div class="bubble">${escapeHtml(m.from + ": " + text)}<div class="bubble-meta"><span>${fmtClock(m.ts)}</span></div></div>`;
      box.appendChild(row);
    }
    box.scrollTop = box.scrollHeight;
  }

  // ---------- Local (per-device) state ----------
  function loadContacts() { try { return JSON.parse(localStorage.getItem(CONTACTS_KEY)) || []; } catch (e) { return []; } }
  function saveContacts(list) { localStorage.setItem(CONTACTS_KEY, JSON.stringify(list)); }
  function addContact(username) {
    const list = loadContacts();
    if (!list.includes(username)) { list.unshift(username); saveContacts(list); }
    return list;
  }

  // ================= AUTH FLOW =================
  function showStep(id) {
    document.querySelectorAll(".auth-step").forEach(el => el.classList.add("hidden"));
    $(id).classList.remove("hidden");
  }

  let pendingHandle = null;
  let pendingAccount = null;

  async function loadAccount(handle) {
    return api(`/api/auth/account/${encodeURIComponent(handle)}`);
  }

  $("create-account-btn").addEventListener("click", async () => {
    const handle = $("handle-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    const passphrase = $("passphrase-input").value;
    const msg = $("handle-msg");
    if (!handle) { msg.textContent = "Pick a handle."; return; }
    if (!passphrase || passphrase.length < 8) { msg.textContent = "Use a passphrase of at least 8 characters."; return; }
    msg.textContent = "Generating your encrypted identity…";
    try {
      const identity = await generateIdentity();
      const wrapped = await wrapPrivateKey(identity.privateJwk, passphrase);
      const data = await api("/api/auth/create", {
        method: "POST",
        body: JSON.stringify({ handle, publicKey: identity.publicJwk, ...wrapped })
      });
      me = { sessionToken: data.sessionToken, handle: data.handle, privateKey: identity.privateKey, publicKey: identity.publicKey, publicJwk: identity.publicJwk };
      persistSession();
      persistDeviceKey(identity.privateJwk, identity.publicJwk);
      showStep("step-whatsapp-prompt");
    } catch (e) { msg.textContent = e.message; }
  });

  $("existing-account-btn").addEventListener("click", async () => {
    const handle = $("handle-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    const msg = $("handle-msg");
    if (!handle) { msg.textContent = "Enter your handle first."; return; }
    msg.textContent = "Finding account…";
    try {
      pendingAccount = await loadAccount(handle);
      pendingHandle = pendingAccount.handle;
      $("unlock-handle").textContent = pendingHandle;
      showStep("step-unlock");
      msg.textContent = "";
    } catch (e) { msg.textContent = e.message; }
  });

  $("unlock-btn").addEventListener("click", async () => {
    const passphrase = $("unlock-passphrase-input").value;
    const msg = $("unlock-msg");
    if (!passphrase) { msg.textContent = "Enter your passphrase."; return; }
    msg.textContent = "Unlocking…";
    try {
      const b = pendingAccount;
      const privateJwk = await unwrapPrivateKey(b.encryptedPrivateKey, b.iv, b.salt, passphrase);
      me = { handle: b.handle, publicJwk: b.publicKey };
      me.privateKey = await importPrivate(privateJwk);
      me.publicKey = await importPublic(me.publicJwk);
      // Exchange the handle for a normal session after local key unlock.
      const login = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ handle: b.handle }) });
      me.sessionToken = login.sessionToken;
      persistSession();
      persistDeviceKey(privateJwk, me.publicJwk);
      enterApp();
    } catch (e) { msg.textContent = "Wrong passphrase, or something went wrong."; }
  });


  $("back-to-handle-btn").addEventListener("click", () => showStep("step-handle"));
  $("link-whatsapp-no-btn").addEventListener("click", () => enterApp());
  $("link-whatsapp-yes-btn").addEventListener("click", async () => { await enterApp(); openWhatsAppLink(); });

  function persistSession() {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ sessionToken: me.sessionToken, handle: me.handle }));
  }
  function persistDeviceKey(privateJwk, publicJwk) {
    localStorage.setItem(DEVICE_KEY_KEY, JSON.stringify({ privateKey: privateJwk, publicKey: publicJwk }));
  }

  function signOut() {
    if (!confirm("Sign out on this device? You can sign back in with your handle and passphrase.")) return;
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(DEVICE_KEY_KEY);
    localStorage.removeItem(CONTACTS_KEY);
    location.reload();
  }

  // ================= MAIN APP =================
  async function enterApp() {
    document.querySelectorAll("#auth-screen, #whatsapp-link-screen").forEach(el => el.style.display = "none");
    $("app-screen").style.display = "block";
    $("me-name").textContent = me.handle;
    $("me-avatar").textContent = initials(me.handle);
    renderContacts();
    connectSocket();
    checkBridge();
    loadGroups();
  }

  function connectSocket() {
    socket = io();
    socket.on("connect", () => {
      socket.emit("identify", me.sessionToken);
      $("conn-status").textContent = "● connected";
      $("conn-status").classList.add("online");
    });
    socket.on("disconnect", () => {
      $("conn-status").textContent = "○ reconnecting…";
      $("conn-status").classList.remove("online");
    });
    socket.on("message:new", async (m) => {
      const other = m.from === me.handle ? m.to : m.from;
      if (other === currentPeer) await appendMessage(m);
      addContact(other);
      renderContacts();
    });
    socket.on("group:message:new", async (m) => {
      if (m.groupId !== currentGroupId) return;
      const text = await decryptFromGroup(m.groupId, m.iv, m.ciphertext);
      const box = $("messages");
      const row = document.createElement("div");
      row.className = "msg-row " + (m.from === me.handle ? "out" : "in");
      row.innerHTML = `<div class="bubble">${escapeHtml(m.from + ": " + text)}<div class="bubble-meta"><span>${fmtClock(m.ts)}</span></div></div>`;
      box.appendChild(row);
      box.scrollTop = box.scrollHeight;
    });
    socket.on("whatsapp:incoming", async (m) => {
      // If the sender has an Ephemeral handle, turn the WhatsApp message into
      // a normal E2EE direct message in the browser. The bridge never stores
      // this plaintext.
      if (!m.fromHandle) return;
      try {
        const { iv, ciphertext } = await encryptFor(m.fromHandle, m.text);
        socket.emit("message:send", { to: m.fromHandle, iv, ciphertext, viaWhatsApp: true });
      } catch (e) { console.error("Could not import WhatsApp message", e); }
    });
  }

  async function checkBridge() {
    try {
      const data = await api("/api/whatsapp/status");
      const hint = $("bridge-hint");
      if (data.linked) {
        hint.classList.remove("hidden");
        hint.innerHTML = data.state === "open"
          ? `<b>WhatsApp is linked.</b> Open your merged inbox.`
          : `<b>WhatsApp isn't fully connected.</b> Tap to view the QR again.`;
        hint.onclick = () => data.state === "open" ? openChat(data.bridgeHandle) : openWhatsAppLink();
      } else {
        hint.classList.remove("hidden");
        hint.innerHTML = `<b>Link WhatsApp</b> — mirror your messages into this app.`;
        hint.onclick = () => openWhatsAppLink();
      }
    } catch (e) { /* optional */ }
  }

  async function openWhatsAppLink() {
    $("whatsapp-link-screen").classList.remove("hidden");
    $("whatsapp-link-screen").style.display = "flex";
    $("wa-qr-box").innerHTML = `<div id="wa-qr-loading">generating QR…</div>`;
    $("wa-link-msg").textContent = "";

    try { await api("/api/whatsapp/link", { method: "POST" }); } catch (e) { $("wa-link-msg").textContent = e.message; }

    const poll = setInterval(async () => {
      try {
        const status = await api("/api/whatsapp/status");
        if (status.state === "open") {
          clearInterval(poll);
          $("wa-link-msg").textContent = "Connected. Sending a confirmation code to your own WhatsApp chat…";
          try {
            await api("/api/whatsapp/request-link-code", { method: "POST" });
            $("wa-code-area").classList.remove("hidden");
            $("wa-link-msg").textContent = "Check your WhatsApp self-chat for the 6-digit code.";
          } catch (e) { $("wa-link-msg").textContent = e.message; }
          return;
        }
        const qrResp = await fetch("/api/whatsapp/qr", { headers: { Authorization: `Bearer ${me.sessionToken}` } });
        if (qrResp.ok) {
          const blob = await qrResp.blob();
          $("wa-qr-box").innerHTML = `<img src="${URL.createObjectURL(blob)}" alt="WhatsApp QR code">`;
        }
      } catch (e) { /* keep polling */ }
    }, 2500);

    $("verify-wa-code-btn").onclick = async () => {
      const code = $("wa-code-input").value.trim();
      if (!code) return;
      try {
        await api("/api/whatsapp/verify-link-code", { method: "POST", body: JSON.stringify({ code }) });
        $("wa-link-msg").textContent = "WhatsApp linked successfully.";
        setTimeout(() => { $("whatsapp-link-screen").style.display = "none"; checkBridge(); }, 500);
      } catch (e) { $("wa-link-msg").textContent = e.message; }
    };
    $("skip-whatsapp-link-btn").onclick = () => { clearInterval(poll); $("whatsapp-link-screen").style.display = "none"; };
  }

  function renderContacts() {
    const list = loadContacts();
    const box = $("contacts");
    if (list.length === 0 && myGroups.length === 0) {
      box.innerHTML = `<div id="contacts-empty">No conversations yet. Enter someone's handle above.</div>`;
      return;
    }
    box.innerHTML = "";
    myGroups.forEach(g => {
      const el = document.createElement("div");
      el.className = "contact" + (currentGroupId === g.id ? " active" : "");
      el.innerHTML = `
        <div class="avatar">${initials(g.name)}</div>
        <div style="min-width:0;">
          <div class="contact-name">${escapeHtml(g.name)}</div>
          <div class="contact-meta">group chat</div>
        </div>`;
      el.onclick = () => openGroup(g.id, g.name);
      box.appendChild(el);
    });
    list.forEach(username => {
      const displayName = username.startsWith("wa-") ? "WhatsApp" : username;
      const el = document.createElement("div");
      el.className = "contact" + (currentPeer === username ? " active" : "");
      el.innerHTML = `
        <div class="avatar">${initials(displayName)}</div>
        <div style="min-width:0;">
          <div class="contact-name">${escapeHtml(displayName)}</div>
          <div class="contact-meta">end-to-end encrypted</div>
        </div>`;
      el.onclick = () => openChat(username);
      box.appendChild(el);
    });
  }

  async function openChat(peer) {
    if (peer === me.handle) return;
    try { await getSharedKey(peer); } catch (e) { alert(`No one with the handle "${peer}" has registered yet.`); return; }
    currentGroupId = null;
    currentPeer = peer;
    addContact(peer);
    renderContacts();

    const isBridge = peer.startsWith("wa-");
    $("chat-empty").style.display = "none";
    $("chat-active").style.display = "flex";
    $("peer-avatar").textContent = initials(isBridge ? "WhatsApp" : peer);
    $("chat-peer-name").textContent = isBridge ? "WhatsApp" : peer;
    $("merged-inbox-warning").classList.toggle("hidden", !isBridge);
    $("fingerprint").textContent = "verifying…";
    fingerprintFor(peer).then(fp => { $("fingerprint").textContent = fp; });

    const msgs = await api(`/api/messages/${encodeURIComponent(peer)}`);
    const box = $("messages");
    box.innerHTML = "";
    for (const m of msgs) await appendMessage(m, { scroll: false });
    box.scrollTop = box.scrollHeight;
  }

  async function appendMessage(m, opts = {}) {
    if (!currentPeer) return;
    const other = m.from === me.handle ? m.to : m.from;
    if (other !== currentPeer) return;
    if ((Date.now() - m.ts) >= THREE_DAYS_MS) return;

    const box = $("messages");
    const outgoing = m.from === me.handle;
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
    if (!text || (!currentPeer && !currentGroupId)) return;
    input.value = "";
    try {
      if (currentGroupId) {
        const { iv, ciphertext } = await encryptForGroup(currentGroupId, text);
        socket.emit("group:send", { groupId: currentGroupId, iv, ciphertext }, (ack) => {
          if (!ack || !ack.ok) alert("Message failed to send: " + (ack && ack.error));
        });
        return;
      }
      const { iv, ciphertext } = await encryptFor(currentPeer, text);
      let relay = null;
      if (!currentPeer.startsWith("wa-") && peerWhatsappLinked[currentPeer]) {
        try { relay = await encryptFor(`wa-${currentPeer}`, text); } catch (e) { /* best-effort relay */ }
      }
      socket.emit("message:send", { to: currentPeer, iv, ciphertext, relay }, (ack) => {
        if (!ack || !ack.ok) alert("Message failed to send: " + (ack && ack.error));
      });
    } catch (e) { alert("Couldn't send — " + e.message); }
  }

  // ---------- Wire up ----------
  $("reset-btn").addEventListener("click", signOut);
  $("new-chat-btn").addEventListener("click", () => {
    const v = $("new-chat-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    if (v) { openChat(v); $("new-chat-input").value = ""; }
  });
  $("new-chat-input").addEventListener("keydown", e => { if (e.key === "Enter") $("new-chat-btn").click(); });
  $("new-group-btn").addEventListener("click", createGroup);
  $("send-btn").addEventListener("click", sendMessage);
  $("compose-input").addEventListener("keydown", e => { if (e.key === "Enter") sendMessage(); });
  $("unlock-passphrase-input").addEventListener("keydown", e => { if (e.key === "Enter") $("unlock-btn").click(); });

  // ---------- Boot: resume an existing device session if we have one ----------
  (async function init() {
    const rawSession = localStorage.getItem(SESSION_KEY);
    const rawKey = localStorage.getItem(DEVICE_KEY_KEY);
    if (!rawSession || !rawKey) return; // show auth-screen (default visible)
    try {
      const session = JSON.parse(rawSession);
      const keys = JSON.parse(rawKey);
      me = {
        phone: session.phone, sessionToken: session.sessionToken, handle: session.handle,
        privateKey: await importPrivate(keys.privateKey),
        publicKey: await importPublic(keys.publicKey),
        publicJwk: keys.publicKey
      };
      enterApp();
    } catch (e) { /* fall through to auth screen */ }
  })();

})();
