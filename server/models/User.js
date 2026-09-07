const mongoose = require("mongoose");

// The server stores a PUBLIC key always, and - for real (non-bridge)
// accounts - an ENCRYPTED backup of the private key so the same account
// can be unlocked from other devices. That backup is wrapped client-side
// with a key derived from a passphrase the server never sees (PBKDF2 ->
// AES-GCM). The server can't decrypt encryptedPrivateKey; it's just
// custody of ciphertext, the same trust model as the messages themselves.
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  phone: { type: String, unique: true, sparse: true, index: true },
  whatsappNumber: { type: String, unique: true, sparse: true, index: true }, // verified linked WhatsApp number
  publicKey: { type: Object, required: true }, // JWK

  // Passphrase-wrapped private key backup (absent for bridge pseudo-accounts,
  // whose private keys are held directly by the server - see index.js).
  encryptedPrivateKey: { type: String },
  ivBackup: { type: String },
  saltBackup: { type: String },

  isBridge: { type: Boolean, default: false },
  owner: { type: String, default: null }, // for isBridge users: the real handle that owns this bridge

  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("User", userSchema);
