const mongoose = require("mongoose");

const THREE_DAYS_SECONDS = 60 * 60 * 24 * 3;

// createdAt has a TTL index: MongoDB itself deletes the document ~3 days
// after creation, server-side, without any app code having to remember
// to prune. iv/ciphertext are opaque base64 blobs - the server never
// sees plaintext for messages between two ordinary users.
const messageSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, index: true }, // "alice|bob" (sorted)
  from: { type: String, required: true },
  to: { type: String, required: true },
  iv: { type: String, required: true },
  ciphertext: { type: String, required: true },
  meta: {
    externalNumber: { type: String, default: null },
    externalName: { type: String, default: null }
  },
  createdAt: { type: Date, default: Date.now, expires: THREE_DAYS_SECONDS }
});

module.exports = mongoose.model("Message", messageSchema);
