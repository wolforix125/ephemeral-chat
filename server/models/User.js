const mongoose = require("mongoose");

// The server only ever stores a username and a PUBLIC key.
// Private keys are generated and kept in the browser (localStorage) and
// are never transmitted here. This is what makes the chat end-to-end
// encrypted: the server can relay and store ciphertext, but has no key
// that lets it read it (except for the special "whatsapp" bridge user -
// see whatsapp.js - which is a real endpoint the server operates on your
// behalf, the same way any bridge/bot participant in a chat can read
// what's sent directly to it).
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  publicKey: { type: Object, required: true }, // JWK
  isBridge: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("User", userSchema);
