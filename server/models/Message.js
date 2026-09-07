const mongoose = require("mongoose");

const THIRTY_SIX_HOURS_SECONDS = 60 * 60 * 36;

// createdAt has a TTL index: MongoDB itself deletes the document ~36 hours
// after creation, server-side, without any app code having to remember
// to prune. iv/ciphertext are opaque base64 blobs - the server never
// sees plaintext for messages between two ordinary users.
const messageSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, index: true }, // "alice|bob" or "group:<id>"
  from: { type: String, required: true },
  to: { type: String, required: true },
  iv: { type: String, required: true },
  ciphertext: { type: String, required: true },
  meta: {
    externalNumber: { type: String, default: null },
    externalName: { type: String, default: null }
  },
  createdAt: { type: Date, default: Date.now, expires: THIRTY_SIX_HOURS_SECONDS }
});

module.exports = mongoose.model("Message", messageSchema);
