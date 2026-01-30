const express = require("express");
const crypto = require("crypto");
const multer = require("multer");
const auth = require("../middleware/auth");
const { pinFileToIPFS } = require("../config/pinata");

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }
});

const sha256Hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

router.post("/ipfs/upload", auth, upload.single("file"), async (req, res) => {
  try {
    if (req.user.role !== "manufacturer") return res.status(403).json({ message: "Only manufacturer can upload files" });

    const f = req.file;
    if (!f || !f.buffer) return res.status(400).json({ message: "Missing file" });

    const file_sha256 = sha256Hex(f.buffer);

    const pinned = await pinFileToIPFS({
      fileBuffer: f.buffer,
      filename: f.originalname || "file",
      mimeType: f.mimetype || "application/octet-stream"
    });

    return res.status(201).json({
      ipfs_cid: pinned.ipfs_cid,
      ipfs_url: pinned.ipfs_url,
      file_sha256
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

module.exports = router;