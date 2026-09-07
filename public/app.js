(function () {
  "use strict";

  const THIRTY_SIX_HOURS_MS = 36 * 60 * 60 * 1000;
  const SESSION_KEY = "ephemeral:session";
  const DEVICE_KEY_KEY = "ephemeral:devicekey";
  const CONTACTS_KEY = "ephemeral:contacts";
  const GROUPS_KEY = "ephemeral:groups";
  const META_KEY = "ephemeral:chatmeta";

  let me = null;
  let socket = null;
  let sharedKeyCache = {};
  let peerPubJwkCache = {};
  let groupKeyCache = {};
  let currentPeer = null;
  let currentChatType = null;
  let pendingCreateToken = null;
  let pendingPhone = null;
  let pendingHandleRequest = null;
  let pendingRequestPoll = null;
  let onlineUsers = new Set();
  let lastSeenUsers = new Map();
  let deleteAfter15Messages = false;

  async function loadRetentionSetting() {
    try {
      const settings = await api("/api/settings");
      deleteAfter15Messages = !!settings.deleteAfter15Messages;
      updateRetentionToggle();
    } catch {}
  }

  async function saveRetentionSetting(enabled) {
    try {
      const settings = await api("/api/settings", {
        method: "POST",
        body: JSON.stringify({ deleteAfter15Messages: enabled })
      });
      deleteAfter15Messages = !!settings.deleteAfter15Messages;
      updateRetentionToggle();
    } catch (e) {
      alert("Couldn't update message retention: " + e.message);
      const toggle = $("delete-after-15-toggle");
      if (toggle) toggle.checked = deleteAfter15Messages;
    }
  }

  function updateRetentionToggle() {
    const toggle = $("delete-after-15-toggle");
    const label = $("retention-toggle-label");
    if (toggle) toggle.checked = deleteAfter15Messages;
    if (label) label.textContent = deleteAfter15Messages ? "keep last 15" : "36h retention";
    const badge = $("expiry-badge");
    if (badge) badge.textContent = deleteAfter15Messages
      ? "messages vanish after 36h · keep last 15"
      : "messages vanish after 36 hours";
  }


  const $ = (id) => document.getElementById(id);

  function b64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function unb64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer; }
  function initials(name) { return (name || "?").slice(0, 2).toUpperCase(); }
  function escapeHtml(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
  function fmtClock(ts) { return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  function timeLeftLabel(ts) {
    const remain = (ts + THIRTY_SIX_HOURS_MS) - Date.now();
    if (remain <= 0) return "expired";
    const h = Math.floor(remain / 3600000);
    const d = Math.floor(h / 24);
    const hh = h % 24;
    if (d > 0) return `${d}d ${hh}h left`;
    const m = Math.floor((remain % 3600000) / 60000);
    if (h > 0) return `${h}h ${m}m left`;
    return `${m}m left`;
  }
  function loadJSON(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } }
  function saveJSON(key, value) { localStorage.setItem(key, JSON.stringify(value)); }
  function loadContacts() { return loadJSON(CONTACTS_KEY, []); }
  function saveContacts(list) { saveJSON(CONTACTS_KEY, list); }
  function loadGroups() { return loadJSON(GROUPS_KEY, []); }
  function saveGroups(list) { saveJSON(GROUPS_KEY, list); }
  function loadMeta() { return loadJSON(META_KEY, {}); }
  function saveMeta(meta) { saveJSON(META_KEY, meta); }
  function metaFor(key) { return loadMeta()[key] || null; }
  function setMeta(key, value) { const meta = loadMeta(); meta[key] = value; saveMeta(meta); }
  function previewText(text) { return String(text || "").replace(/\s+/g, " ").slice(0, 80); }
  function lastSeenLabel(ts) {
    if (!ts) return "offline";
    const date = new Date(ts);
    const now = Date.now();
    const diff = Math.max(0, now - date.getTime());
    if (diff < 60 * 1000) return "last seen just now";
    if (diff < 60 * 60 * 1000) return `last seen ${Math.floor(diff / 60000)}m ago`;
    if (date.toDateString() === new Date().toDateString()) return `last seen today at ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    return `last seen ${date.toLocaleDateString([], { day: "numeric", month: "short" })} at ${date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  }

  async function api(path, opts = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (me && me.sessionToken) headers.Authorization = `Bearer ${me.sessionToken}`;
    const resp = await fetch(path, Object.assign({}, opts, { headers }));
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `request failed (${resp.status})`);
    return data;
  }

  // ---------- Identity crypto ----------
  async function generateIdentity() {
    const keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, publicJwk, privateJwk };
  }
  async function importPrivate(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]); }
  async function importPublic(jwk) { return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []); }

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

  // ---------- Direct-message crypto ----------
  async function getSharedKey(peerUsername) {
    if (sharedKeyCache[peerUsername]) return sharedKeyCache[peerUsername];
    const data = await api(`/api/users/${encodeURIComponent(peerUsername)}`);
    peerPubJwkCache[peerUsername] = data.publicKey;
    if (data.lastSeenAt) lastSeenUsers.set(peerUsername, data.lastSeenAt);
    const peerPublicKey = await importPublic(data.publicKey);
    const aesKey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: peerPublicKey }, me.privateKey,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
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
    } catch { return "⚠ could not decrypt this message"; }
  }
  async function fingerprintFor(peerUsername) {
    const peerJwk = peerPubJwkCache[peerUsername];
    if (!peerJwk) return "";
    const combined = [me.publicJwk.x + me.publicJwk.y, peerJwk.x + peerJwk.y].sort().join("|");
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(combined));
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
    return hex.slice(0, 20).match(/.{1,4}/g).join(" ");
  }

  // ---------- Group crypto ----------
  async function getGroupKey(groupId) {
    if (groupKeyCache[groupId]) return groupKeyCache[groupId];
    const group = await api(`/api/groups/${encodeURIComponent(groupId)}`);
    if (!group.wrappedKey) throw new Error("you don't have a key for this group");
    const pairwise = await getSharedKey(me.handle);
    const raw = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(unb64(group.wrappedKey.iv)) },
      pairwise, unb64(group.wrappedKey.ciphertext)
    );
    const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    groupKeyCache[groupId] = key;
    return key;
  }
  async function wrapGroupKeyFor(username, rawGroupKey) {
    const pairwise = await getSharedKey(username);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, pairwise, rawGroupKey);
    return { username, iv: b64(iv), ciphertext: b64(ct) };
  }
  async function encryptForGroup(groupId, plaintext) {
    const key = await getGroupKey(groupId);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
    return { iv: b64(iv), ciphertext: b64(ct) };
  }
  async function decryptFromGroup(groupId, ivB64, ctB64) {
    try {
      const key = await getGroupKey(groupId);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(unb64(ivB64)) }, key, unb64(ctB64));
      return new TextDecoder().decode(pt);
    } catch { return "⚠ could not decrypt this group message"; }
  }

  function addContact(username) {
    const list = loadContacts();
    if (!list.includes(username)) { list.unshift(username); saveContacts(list); }
    return list;
  }
  function addGroup(group) {
    const list = loadGroups();
    const idx = list.findIndex(g => g.id === group.id);
    if (idx >= 0) list[idx] = group; else list.unshift(group);
    saveGroups(list);
  }

  // ================= AUTH FLOW =================
  function showStep(id) {
    document.querySelectorAll(".auth-step").forEach(el => el.classList.add("hidden"));
    $(id).classList.remove("hidden");
  }

  $("send-code-btn").addEventListener("click", async () => {
    const phone = $("phone-input").value.trim().replace(/[^\d]/g, "");
    const msg = $("phone-msg");
    if (phone.length < 6) { msg.textContent = "Enter a valid phone number with country code."; return; }
    msg.textContent = "Sending…";
    try {
      const data = await api("/api/auth/request-code", { method: "POST", body: JSON.stringify({ phone }) });
      pendingPhone = phone;
      $("code-lede").textContent = data.deliveredVia === "dev-console"
        ? `DEV MODE — your code is ${data.devCode}`
        : "We sent a 6-digit code over WhatsApp.";
      msg.textContent = "";
      showStep("step-code");
    } catch (e) { msg.textContent = e.message; }
  });
  $("back-to-phone-btn").addEventListener("click", () => showStep("step-phone"));

  $("verify-code-btn").addEventListener("click", async () => {
    const code = $("code-input").value.trim();
    const msg = $("code-msg");
    if (!code) { msg.textContent = "Enter the code."; return; }
    msg.textContent = "Verifying…";
    try {
      const data = await api("/api/auth/verify", { method: "POST", body: JSON.stringify({ phone: pendingPhone, code }) });
      if (data.status === "existing") {
        me = { phone: pendingPhone, sessionToken: data.sessionToken, handle: data.handle, publicJwk: data.publicKey };
        window.__pendingBackup = { encryptedPrivateKey: data.encryptedPrivateKey, iv: data.iv, salt: data.salt };
        $("unlock-handle").textContent = data.handle;
        showStep("step-unlock");
      } else {
        pendingCreateToken = data.createToken;
        $("handle-input").value = "";
        showStep("step-new-account");
      }
    } catch (e) { msg.textContent = e.message; }
  });

  async function requestHandleAccess(handle) {
    const msg = $("new-account-msg");
    msg.textContent = "That handle is already in use. Sending an approval request…";
    try {
      const data = await api("/api/auth/request-handle-access", {
        method: "POST", body: JSON.stringify({ handle, phone: pendingPhone })
      });
      pendingHandleRequest = { requestId: data.requestId, requestToken: data.requestToken };
      $("request-handle").textContent = handle;
      $("request-code").textContent = data.approvalCode || "pending";
      $("request-device").textContent = data.device?.deviceName || "this device";
      $("handle-request-msg").textContent = "Waiting for the account owner to accept or decline…";
      showStep("step-handle-request");
      if (pendingRequestPoll) clearInterval(pendingRequestPoll);
      pendingRequestPoll = setInterval(checkHandleRequest, 2500);
      await checkHandleRequest();
    } catch (e) { msg.textContent = e.message; }
  }

  async function checkHandleRequest() {
    if (!pendingHandleRequest) return;
    try {
      const data = await fetch(`/api/auth/handle-request/${encodeURIComponent(pendingHandleRequest.requestId)}?token=${encodeURIComponent(pendingHandleRequest.requestToken)}`).then(async r => {
        const d = await r.json(); if (!r.ok) throw new Error(d.error || "request failed"); return d;
      });
      if (data.status === "approved") {
        clearInterval(pendingRequestPoll); pendingRequestPoll = null;
        me = { phone: pendingPhone, sessionToken: data.sessionToken, handle: data.handle, publicJwk: data.publicKey };
        window.__pendingBackup = { encryptedPrivateKey: data.encryptedPrivateKey, iv: data.iv, salt: data.salt };
        $("unlock-handle").textContent = data.handle;
        showStep("step-unlock");
        $("unlock-msg").textContent = "The owner approved this device. Enter your recovery passphrase.";
      } else if (data.status === "declined" || data.status === "expired") {
        clearInterval(pendingRequestPoll); pendingRequestPoll = null;
        $("handle-request-msg").textContent = data.status === "declined" ? "The account owner declined this request." : "This request expired. Try again.";
      }
    } catch (e) {
      // A request can disappear when Mongo's TTL removes it. Keep the UI calm until the next poll.
    }
  }

  $("cancel-handle-request-btn").addEventListener("click", () => {
    if (pendingRequestPoll) clearInterval(pendingRequestPoll);
    pendingRequestPoll = null; pendingHandleRequest = null;
    showStep("step-new-account");
  });

  $("create-account-btn").addEventListener("click", async () => {
    const handle = $("handle-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "");
    const passphrase = $("passphrase-input").value;
    const msg = $("new-account-msg");
    if (!handle) { msg.textContent = "Pick a handle."; return; }
    if (!passphrase || passphrase.length < 8) { msg.textContent = "Use a passphrase of at least 8 characters."; return; }
    msg.textContent = "Generating your key pair…";
    try {
      const identity = await generateIdentity();
      const wrapped = await wrapPrivateKey(identity.privateJwk, passphrase);
      const data = await api("/api/auth/create", {
        method: "POST", body: JSON.stringify({ createToken: pendingCreateToken, handle, publicKey: identity.publicJwk, ...wrapped })
      });
      me = { phone: pendingPhone, sessionToken: data.sessionToken, handle: data.handle, privateKey: identity.privateKey, publicKey: identity.publicKey, publicJwk: identity.publicJwk };
      persistSession(); persistDeviceKey(identity.privateJwk, identity.publicJwk);
      showStep("step-whatsapp-prompt");
    } catch (e) {
      if (e.message === "handle already taken") await requestHandleAccess(handle);
      else msg.textContent = e.message;
    }
  });

  $("unlock-btn").addEventListener("click", async () => {
    const passphrase = $("unlock-passphrase-input").value;
    const msg = $("unlock-msg");
    if (!passphrase) { msg.textContent = "Enter your passphrase."; return; }
    msg.textContent = "Unlocking…";
    try {
      const b = window.__pendingBackup;
      const privateJwk = await unwrapPrivateKey(b.encryptedPrivateKey, b.iv, b.salt, passphrase);
      me.privateKey = await importPrivate(privateJwk);
      me.publicKey = await importPublic(me.publicJwk);
      persistSession(); persistDeviceKey(privateJwk, me.publicJwk);
      enterApp();
    } catch { msg.textContent = "Wrong passphrase, or something went wrong. Try again."; }
  });

  $("link-whatsapp-no-btn").addEventListener("click", () => enterApp());
  $("link-whatsapp-yes-btn").addEventListener("click", async () => { await enterApp(); openWhatsAppLink(); });

  function persistSession() { saveJSON(SESSION_KEY, { sessionToken: me.sessionToken, handle: me.handle, phone: me.phone }); }
  function persistDeviceKey(privateJwk, publicJwk) { saveJSON(DEVICE_KEY_KEY, { privateKey: privateJwk, publicKey: publicJwk }); }
  function signOut() {
    if (!confirm("Sign out on this device? You can sign back in with your phone number and passphrase.")) return;
    localStorage.removeItem(SESSION_KEY); localStorage.removeItem(DEVICE_KEY_KEY); localStorage.removeItem(CONTACTS_KEY);
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
    await refreshInbox();
    await pollLoginRequests();
    await loadRetentionSetting();
    setInterval(pollLoginRequests, 5000);
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
    socket.on("presence:snapshot", list => {
      onlineUsers = new Set(list.filter(x => x.online).map(x => x.username));
      renderContacts(); updateCurrentPeerStatus();
    });
    socket.on("presence:update", ({ username, online }) => {
      if (online) onlineUsers.add(username); else onlineUsers.delete(username);
      renderContacts(); updateCurrentPeerStatus();
    });
    socket.on("auth:handle-request", request => {
      $("login-requests-btn").classList.remove("hidden");
      pollLoginRequests();
      try {
        const notice = `${request.device?.deviceName || "New device"} is requesting access. Confirmation code: ${request.approvalCode}`;
        if (document.visibilityState !== "visible") alert(notice);
      } catch {}
    });
    socket.on("group:created", group => { addGroup(group); renderContacts(); socket.emit("group:join", group.id); });
    socket.on("message:new", async (m) => {
      const other = m.from === me.handle ? m.to : m.from;
      const text = await decryptFrom(other, m.iv, m.ciphertext);
      setMeta(`direct:${other}`, { lastMessage: previewText(text), ts: m.ts });
      addContact(other); renderContacts();
      if (currentChatType === "direct" && other === currentPeer) await appendDirectMessage(m);
    });
    socket.on("group:message:new", async (m) => {
      const text = await decryptFromGroup(m.groupId, m.iv, m.ciphertext);
      setMeta(`group:${m.groupId}`, { lastMessage: previewText(text), ts: m.ts });
      if (currentChatType === "group" && m.groupId === currentPeer) await appendGroupMessage(m);
      renderContacts();
    });
  }

  async function refreshInbox() {
    try {
      const data = await api("/api/inbox");
      data.direct.forEach(item => addContact(item.peer));
      data.groups.forEach(addGroup);
      for (const item of data.direct) {
        const text = await decryptFrom(item.peer, item.iv, item.ciphertext);
        setMeta(`direct:${item.peer}`, { lastMessage: previewText(text), ts: item.ts });
      }
      for (const group of data.groups) {
        try {
          const msgs = await api(`/api/groups/${encodeURIComponent(group.id)}/messages`);
          const last = msgs[msgs.length - 1];
          if (last) {
            const text = await decryptFromGroup(group.id, last.iv, last.ciphertext);
            setMeta(`group:${group.id}`, { lastMessage: previewText(text), ts: last.ts });
          }
        } catch { /* keep the rest of the inbox usable */ }
      }
      renderContacts();
    } catch { /* optional metadata endpoint */ }
  }

  async function pollLoginRequests() {
    try {
      const requests = await api("/api/auth/pending-requests");
      const btn = $("login-requests-btn");
      btn.classList.toggle("hidden", requests.length === 0);
      if (requests.length) showLoginRequestNotification(requests);
    } catch { /* signed-out/expired session */ }
  }

  let shownRequestIds = new Set();
  function showLoginRequestNotification(requests) {
    const unseen = requests.filter(r => !shownRequestIds.has(r.requestId));
    if (!unseen.length) return;
    unseen.forEach(r => shownRequestIds.add(r.requestId));
    renderLoginRequests(requests);
    $("login-requests-modal").classList.remove("hidden");
  }
  function renderLoginRequests(requests) {
    const box = $("login-requests-list"); box.innerHTML = "";
    if (!requests.length) { box.innerHTML = `<div class="empty-small">No pending requests.</div>`; return; }
    requests.forEach(r => {
      const el = document.createElement("div"); el.className = "request-item";
      el.innerHTML = `
        <div class="request-top"><b>New device</b><span>${escapeHtml(r.deviceName)}</span></div>
        <div class="request-details">Phone: ${escapeHtml(r.phone)}<br>Browser: ${escapeHtml(r.browser)} · ${escapeHtml(r.os)}<br>IP: ${escapeHtml(r.ip)}<br>Confirmation code: <strong>${escapeHtml(r.approvalCode)}</strong></div>
        <div class="request-actions"><button class="approve-request">Accept</button><button class="decline-request">Decline</button></div>`;
      el.querySelector(".approve-request").onclick = async () => { try { await api(`/api/auth/handle-request/${r.requestId}/approve`, { method: "POST" }); el.remove(); pollLoginRequests(); } catch (e) { alert(e.message); } };
      el.querySelector(".decline-request").onclick = async () => { try { await api(`/api/auth/handle-request/${r.requestId}/decline`, { method: "POST" }); el.remove(); pollLoginRequests(); } catch (e) { alert(e.message); } };
      box.appendChild(el);
    });
  }

  $("login-requests-btn").addEventListener("click", async () => {
    try { const requests = await api("/api/auth/pending-requests"); renderLoginRequests(requests); $("login-requests-modal").classList.remove("hidden"); } catch {}
  });
  $("close-login-requests-btn").addEventListener("click", () => $("login-requests-modal").classList.add("hidden"));

  async function checkBridge() {
    try {
      const data = await api("/api/whatsapp/status");
      const hint = $("bridge-hint");
      hint.classList.remove("hidden");
      if (data.linked) {
        hint.innerHTML = data.state === "open" ? `<b>WhatsApp is linked.</b> Open your merged inbox.` : `<b>WhatsApp isn't fully connected.</b> Tap to view the QR again.`;
        hint.onclick = () => data.state === "open" ? openChat(data.bridgeHandle) : openWhatsAppLink();
      } else {
        hint.innerHTML = `<b>Link WhatsApp</b> — mirror your messages into this app.`;
        hint.onclick = () => openWhatsAppLink();
      }
    } catch {}
  }
  async function openWhatsAppLink() {
    $("whatsapp-link-screen").classList.remove("hidden"); $("whatsapp-link-screen").style.display = "flex";
    $("wa-qr-box").innerHTML = `<div id="wa-qr-loading">generating QR…</div>`; $("wa-link-msg").textContent = "";
    try { await api("/api/whatsapp/link", { method: "POST" }); } catch (e) { $("wa-link-msg").textContent = e.message; }
    const poll = setInterval(async () => {
      try {
        const status = await api("/api/whatsapp/status");
        if (status.state === "open") { clearInterval(poll); $("whatsapp-link-screen").style.display = "none"; checkBridge(); openChat(status.bridgeHandle); return; }
        const qrResp = await fetch("/api/whatsapp/qr", { headers: { Authorization: `Bearer ${me.sessionToken}` } });
        if (qrResp.ok) { const blob = await qrResp.blob(); $("wa-qr-box").innerHTML = `<img src="${URL.createObjectURL(blob)}" alt="WhatsApp QR code">`; }
      } catch {}
    }, 2500);
    $("skip-whatsapp-link-btn").onclick = () => { clearInterval(poll); $("whatsapp-link-screen").style.display = "none"; };
  }

  function renderContacts() {
    const box = $("contacts"); box.innerHTML = "";
    const contacts = loadContacts(); const groups = loadGroups();
    if (!contacts.length && !groups.length) { box.innerHTML = `<div id="contacts-empty">No conversations yet. Enter someone's handle above.</div>`; return; }
    if (groups.length) {
      const title = document.createElement("div"); title.className = "list-section-title"; title.textContent = "GROUPS"; box.appendChild(title);
      groups.forEach(group => {
        const meta = metaFor(`group:${group.id}`); const el = document.createElement("div");
        el.className = "contact" + (currentChatType === "group" && currentPeer === group.id ? " active" : "");
        el.innerHTML = `<div class="avatar">#</div><div class="contact-main"><div class="contact-name">${escapeHtml(group.name)}</div><div class="contact-meta">${escapeHtml(meta?.lastMessage || `${group.members.length} members`)}</div></div>`;
        el.onclick = () => openGroup(group.id); box.appendChild(el);
      });
    }
    if (contacts.length) {
      const title = document.createElement("div"); title.className = "list-section-title"; title.textContent = "DIRECT"; box.appendChild(title);
      contacts.forEach(username => {
        const displayName = username.startsWith("wa-") ? "WhatsApp" : username;
        const meta = metaFor(`direct:${username}`);
        const online = !username.startsWith("wa-") && onlineUsers.has(username);
        const presenceText = online ? "online" : lastSeenLabel(lastSeenUsers.get(username));
        const el = document.createElement("div");
        el.className = "contact" + (currentChatType === "direct" && currentPeer === username ? " active" : "");
        el.innerHTML = `<div class="avatar-wrap"><div class="avatar">${initials(displayName)}</div>${online ? '<span class="online-dot"></span>' : ''}</div><div class="contact-main"><div class="contact-name">${escapeHtml(displayName)}</div><div class="contact-meta">${escapeHtml(meta?.lastMessage || presenceText)}</div></div>`;
        el.onclick = () => openChat(username); box.appendChild(el);
      });
    }
  }

  function updateCurrentPeerStatus() {
    if (currentChatType !== "direct") return;
    const isBridge = currentPeer && currentPeer.startsWith("wa-");
    $("chat-peer-status").textContent = isBridge ? "WhatsApp · phone-to-phone" : (onlineUsers.has(currentPeer) ? "online" : lastSeenLabel(lastSeenUsers.get(currentPeer)));
    $("chat-peer-status").className = (!isBridge && onlineUsers.has(currentPeer)) ? "online-label" : "offline-label";
  }

  async function openChat(peer) {
    if (peer === me.handle) return;
    try { await getSharedKey(peer); } catch { alert(`No one with the handle "${peer}" has registered yet.`); return; }
    currentPeer = peer; currentChatType = "direct"; addContact(peer); renderContacts();
    const isBridge = peer.startsWith("wa-");
    $("chat-empty").style.display = "none"; $("chat-active").style.display = "flex";
    $("peer-avatar").textContent = initials(isBridge ? "WhatsApp" : peer);
    $("chat-peer-name").textContent = isBridge ? "WhatsApp" : peer;
    $("merged-inbox-warning").classList.toggle("hidden", !isBridge);
    $("fingerprint").textContent = "verifying…";
    fingerprintFor(peer).then(fp => { $("fingerprint").textContent = fp; });
    updateCurrentPeerStatus();
    const msgs = await api(`/api/messages/${encodeURIComponent(peer)}`);
    const box = $("messages"); box.innerHTML = "";
    for (const m of msgs) await appendDirectMessage(m, { scroll: false });
    box.scrollTop = box.scrollHeight;
  }

  async function appendDirectMessage(m, opts = {}) {
    if (currentChatType !== "direct" || !currentPeer) return;
    const other = m.from === me.handle ? m.to : m.from;
    if (other !== currentPeer || (Date.now() - m.ts) >= THIRTY_SIX_HOURS_MS) return;
    const text = await decryptFrom(currentPeer, m.iv, m.ciphertext);
    setMeta(`direct:${currentPeer}`, { lastMessage: previewText(text), ts: m.ts });
    const box = $("messages"); const outgoing = m.from === me.handle;
    const row = document.createElement("div"); row.className = "msg-row " + (outgoing ? "out" : "in");
    row.innerHTML = `<div class="bubble">${escapeHtml(text)}<div class="bubble-meta"><span>${fmtClock(m.ts)}</span><span>·</span><span>${timeLeftLabel(m.ts)}</span></div></div>`;
    box.appendChild(row); if (opts.scroll !== false) box.scrollTop = box.scrollHeight;
  }

  async function openGroup(groupId) {
    const group = loadGroups().find(g => g.id === groupId);
    if (!group) return;
    try { await getGroupKey(groupId); } catch (e) { alert(e.message); return; }
    currentPeer = groupId; currentChatType = "group"; addGroup(group); renderContacts();
    $("chat-empty").style.display = "none"; $("chat-active").style.display = "flex";
    $("peer-avatar").textContent = "#"; $("chat-peer-name").textContent = group.name;
    $("chat-peer-status").textContent = `${group.members.length} members`;
    $("chat-peer-status").className = "offline-label";
    $("merged-inbox-warning").classList.add("hidden"); $("fingerprint").textContent = "group-encrypted";
    const msgs = await api(`/api/groups/${encodeURIComponent(groupId)}/messages`);
    const box = $("messages"); box.innerHTML = "";
    for (const m of msgs) await appendGroupMessage(m, { scroll: false });
    box.scrollTop = box.scrollHeight;
  }

  async function appendGroupMessage(m, opts = {}) {
    if (currentChatType !== "group" || currentPeer !== m.groupId || (Date.now() - m.ts) >= THIRTY_SIX_HOURS_MS) return;
    const text = await decryptFromGroup(m.groupId, m.iv, m.ciphertext);
    setMeta(`group:${m.groupId}`, { lastMessage: previewText(text), ts: m.ts });
    const box = $("messages"); const outgoing = m.from === me.handle;
    const row = document.createElement("div"); row.className = "msg-row " + (outgoing ? "out" : "in");
    row.innerHTML = `<div class="bubble"><div class="sender-label">${escapeHtml(m.from)}</div>${escapeHtml(text)}<div class="bubble-meta"><span>${fmtClock(m.ts)}</span><span>·</span><span>${timeLeftLabel(m.ts)}</span></div></div>`;
    box.appendChild(row); if (opts.scroll !== false) box.scrollTop = box.scrollHeight;
  }

  async function sendMessage() {
    const input = $("compose-input"); const text = input.value.trim();
    if (!text || !currentPeer) return; input.value = "";
    try {
      if (currentChatType === "group") {
        const { iv, ciphertext } = await encryptForGroup(currentPeer, text);
        socket.emit("group:message:send", { groupId: currentPeer, iv, ciphertext }, ack => { if (!ack?.ok) alert("Message failed to send: " + (ack?.error || "unknown error")); });
      } else {
        const { iv, ciphertext } = await encryptFor(currentPeer, text);
        socket.emit("message:send", { to: currentPeer, iv, ciphertext }, ack => { if (!ack?.ok) alert("Message failed to send: " + (ack?.error || "unknown error")); });
      }
    } catch (e) { alert("Couldn't send — " + e.message); }
  }

  // ---------- Group creation ----------
  $("new-group-btn").addEventListener("click", () => { $("group-modal").classList.remove("hidden"); $("group-name-input").focus(); });
  $("close-group-btn").addEventListener("click", () => $("group-modal").classList.add("hidden"));
  $("create-group-confirm-btn").addEventListener("click", async () => {
    const name = $("group-name-input").value.trim();
    const members = $("group-members-input").value.split(",").map(s => s.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, "")).filter(Boolean);
    const msg = $("group-msg");
    if (!name) { msg.textContent = "Enter a group name."; return; }
    if (!members.length) { msg.textContent = "Add at least one member handle."; return; }
    msg.textContent = "Generating group encryption key…";
    try {
      const uniqueMembers = [...new Set([me.handle, ...members])];
      const groupKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
      const rawGroupKey = await crypto.subtle.exportKey("raw", groupKey);
      const wrappedKeys = [];
      for (const username of uniqueMembers) wrappedKeys.push(await wrapGroupKeyFor(username, rawGroupKey));
      const data = await api("/api/groups", { method: "POST", body: JSON.stringify({ name, members: uniqueMembers, wrappedKeys }) });
      groupKeyCache[data.group.id] = groupKey;
      addGroup(data.group); renderContacts(); $("group-modal").classList.add("hidden");
      $("group-name-input").value = ""; $("group-members-input").value = ""; $("group-msg").textContent = "";
      openGroup(data.group.id);
    } catch (e) { msg.textContent = e.message; }
  });

  // ---------- Wire up ----------
  $("reset-btn").addEventListener("click", signOut);
  $("new-chat-btn").addEventListener("click", () => { const v = $("new-chat-input").value.trim().toLowerCase().replace(/[^a-z0-9_.-]/g, ""); if (v) { openChat(v); $("new-chat-input").value = ""; } });
  $("new-chat-input").addEventListener("keydown", e => { if (e.key === "Enter") $("new-chat-btn").click(); });
  $("delete-after-15-toggle").addEventListener("change", e => saveRetentionSetting(e.target.checked));
  $("send-btn").addEventListener("click", sendMessage);
  $("compose-input").addEventListener("keydown", e => { if (e.key === "Enter") sendMessage(); });
  $("phone-input").addEventListener("keydown", e => { if (e.key === "Enter") $("send-code-btn").click(); });
  $("code-input").addEventListener("keydown", e => { if (e.key === "Enter") $("verify-code-btn").click(); });
  $("unlock-passphrase-input").addEventListener("keydown", e => { if (e.key === "Enter") $("unlock-btn").click(); });

  // ---------- Boot ----------
  (async function init() {
    const rawSession = localStorage.getItem(SESSION_KEY);
    const rawKey = localStorage.getItem(DEVICE_KEY_KEY);
    if (!rawSession || !rawKey) return;
    try {
      const session = JSON.parse(rawSession); const keys = JSON.parse(rawKey);
      me = { phone: session.phone, sessionToken: session.sessionToken, handle: session.handle, privateKey: await importPrivate(keys.privateKey), publicKey: await importPublic(keys.publicKey), publicJwk: keys.publicKey };
      enterApp();
    } catch { /* show auth */ }
  })();
})();
