/**
 * A MongoDB-backed replacement for Baileys' useMultiFileAuthState, namespaced
 * per app-user so several people can each link their own WhatsApp account on
 * the same deployment. Mirrors the official multi-file implementation
 * (see @whiskeysockets/baileys/lib/Utils/use-multi-file-auth-state.js) but
 * writes to Mongo instead of the filesystem - which matters on hosts like
 * Render's free tier where local disk isn't guaranteed to survive a redeploy.
 */

const mongoose = require("mongoose");
const { proto, initAuthCreds, BufferJSON } = require("@whiskeysockets/baileys");

const authKeySchema = new mongoose.Schema({
  _id: { type: String }, // `${ownerUsername}::${key}`, e.g. "river::creds"
  raw: { type: String, required: true }
});
const AuthKey = mongoose.models.WhatsAppAuthKey || mongoose.model("WhatsAppAuthKey", authKeySchema);

async function useMongoAuthState(ownerUsername) {
  const ns = (key) => `${ownerUsername}::${key}`;

  const writeData = async (data, key) => {
    const raw = JSON.stringify(data, BufferJSON.replacer);
    await AuthKey.findByIdAndUpdate(ns(key), { raw }, { upsert: true });
  };
  const readData = async (key) => {
    const doc = await AuthKey.findById(ns(key)).lean();
    if (!doc) return null;
    try { return JSON.parse(doc.raw, BufferJSON.reviver); } catch (e) { return null; }
  };
  const removeData = async (key) => {
    await AuthKey.deleteOne({ _id: ns(key) }).catch(() => {});
  };

  const creds = (await readData("creds")) || initAuthCreds();

  return {
    state: {
      creds,
      keys: {
        get: async (type, ids) => {
          const data = {};
          await Promise.all(ids.map(async (id) => {
            let value = await readData(`${type}-${id}`);
            if (type === "app-state-sync-key" && value) {
              value = proto.Message.AppStateSyncKeyData.fromObject(value);
            }
            data[id] = value;
          }));
          return data;
        },
        set: async (data) => {
          const tasks = [];
          for (const category in data) {
            for (const id in data[category]) {
              const value = data[category][id];
              const key = `${category}-${id}`;
              tasks.push(value ? writeData(value, key) : removeData(key));
            }
          }
          await Promise.all(tasks);
        }
      }
    },
    saveCreds: () => writeData(creds, "creds")
  };
}

async function clearMongoAuthState(ownerUsername) {
  await AuthKey.deleteMany({ _id: { $regex: `^${ownerUsername}::` } });
}

module.exports = { useMongoAuthState, clearMongoAuthState };
