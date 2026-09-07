const mongoose = require("mongoose");

const wrappedKeySchema = new mongoose.Schema({
  username: { type: String, required: true },
  iv: { type: String, required: true },
  ciphertext: { type: String, required: true }
}, { _id: false });

const groupSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  owner: { type: String, required: true, index: true },
  members: [{ type: String, required: true }],
  wrappedKeys: { type: [wrappedKeySchema], default: [] },
  createdAt: { type: Date, default: Date.now }
});

groupSchema.index({ members: 1 });

module.exports = mongoose.model("Group", groupSchema);
