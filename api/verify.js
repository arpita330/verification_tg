require("dotenv").config();
const crypto = require("crypto");
const { encrypt, decrypt } = require("../utils/crypto");

/* Replace with MongoDB in production */
let usersDB = {};

function verifyTelegram(initData) {
  const urlParams = new URLSearchParams(initData);
  const hash = urlParams.get("hash");
  urlParams.delete("hash");

  const dataCheckString = [...urlParams.entries()]
    .sort()
    .map(([key, val]) => `${key}=${val}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.BOT_TOKEN)
    .digest();

  const hmac = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  return hmac === hash;
}

module.exports = async (req, res) => {
  try {

    if (req.method !== "POST") {
      return res.status(405).json({ status: "method_not_allowed" });
    }

    const { initData, fingerprint } = req.body;

    if (!verifyTelegram(initData)) {
      return res.status(403).json({ status: "invalid_telegram_signature" });
    }

    const params = new URLSearchParams(initData);
    const user = JSON.parse(params.get("user"));
    const userId = user.id;

    const encryptedFingerprint = encrypt(fingerprint);

    /* FIRST TIME */
    if (!usersDB[userId]) {
      usersDB[userId] = {
        device: encryptedFingerprint,
        locked: false
      };

      return res.json({ status: "verified_first_time" });
    }

    /* IF LOCKED */
    if (usersDB[userId].locked === true) {
      return res.json({ status: "device_locked" });
    }

    /* CHECK DEVICE */
    const storedFingerprint = decrypt(usersDB[userId].device);

    if (storedFingerprint === fingerprint) {
      return res.json({ status: "verified" });
    }

    /* DIFFERENT DEVICE → PERMANENT LOCK */
    usersDB[userId].locked = true;

    return res.json({ status: "device_locked" });

  } catch (err) {
    return res.status(500).json({ status: "server_error", error: err.message });
  }
};
