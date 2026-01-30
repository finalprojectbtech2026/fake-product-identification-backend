const crypto = require("crypto");

const sha256Hex = (input) => crypto.createHash("sha256").update(String(input)).digest("hex");
const sha256Bytes32 = (input) => "0x" + sha256Hex(input);

module.exports = { sha256Hex, sha256Bytes32 };