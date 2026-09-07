const mongoose = require("mongoose");

// Short-lived verification codes. TTL index means Mongo deletes expired
// codes on its own - nothing lingers.
const otpSchema = new mongoose.Schema({
  phone: { type: String, required: true, unique: true, index: true },
  codeHash: { type: String, required: true },
  attempts: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now, expires: 60 * 10 } // 10 minutes
});

module.exports = mongoose.model("Otp", otpSchema);
