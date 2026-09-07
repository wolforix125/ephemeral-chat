const mongoose = require("mongoose");

const TEN_MINUTES = 10 * 60;

const loginRequestSchema = new mongoose.Schema({
  requestId: { type: String, required: true, unique: true, index: true },
  targetHandle: { type: String, required: true, index: true },
  phone: { type: String, required: true },
  approvalCodeHash: { type: String, required: true },
  approvalCode: { type: String, required: true },
  status: { type: String, enum: ["pending", "approved", "declined", "expired"], default: "pending", index: true },
  deviceName: { type: String, default: "Unknown device" },
  browser: { type: String, default: "Unknown browser" },
  os: { type: String, default: "Unknown OS" },
  ip: { type: String, default: "unknown" },
  userAgent: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now, expires: TEN_MINUTES }
});

module.exports = mongoose.model("LoginRequest", loginRequestSchema);
