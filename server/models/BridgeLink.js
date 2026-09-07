const mongoose = require("mongoose");

// One row per app user who has linked WhatsApp. In "mirror" mode there is
// no single fixed contact - any inbound WhatsApp message auto-creates/uses
// this merged thread. lastExternalSender is who a reply from the app gets
// routed to, since a merged inbox has no single "peer" to address.
const bridgeLinkSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  bridgeHandle: { type: String, required: true },
  lastExternalSender: { type: String, default: null }, // phone digits
  lastExternalSenderName: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("BridgeLink", bridgeLinkSchema);
