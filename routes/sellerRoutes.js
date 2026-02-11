// D:\fpi\backend\routes\sellerRoutes.js
const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { contract, ethers } = require("../config/blockchain");

const router = express.Router();

const normalizeWallet = (w) => {
  const v = String(w || "").trim();
  if (!v) return "";
  try {
    return ethers.getAddress(v);
  } catch {
    return "";
  }
};

router.post("/manufacturer/link-wallet", auth, async (req, res) => {
  try {
    if (String(req.user?.role || "").toLowerCase() !== "manufacturer") {
      return res.status(403).json({ message: "Only manufacturer can link wallet" });
    }

    const wallet = normalizeWallet(req.body.wallet_address);
    if (!wallet) return res.status(400).json({ message: "Invalid wallet_address" });

    const u = await pool.query("SELECT approval_status FROM users WHERE id=$1", [req.user.userId]);
    if (u.rowCount === 0) return res.status(404).json({ message: "User not found" });

    const st = String(u.rows[0].approval_status || "").toUpperCase();
    if (st !== "APPROVED") return res.status(403).json({ message: "Manufacturer not approved yet", approval_status: st });

    await pool.query("UPDATE users SET wallet_address=$1 WHERE id=$2", [wallet, req.user.userId]);

    return res.status(200).json({ wallet_address: wallet });
  } catch (e) {
    const msg = String(e?.message || e);
    if (msg.toLowerCase().includes("duplicate") || msg.toLowerCase().includes("unique")) {
      return res.status(409).json({ message: "Wallet already linked to another account" });
    }
    return res.status(500).json({ message: "Server error", error: msg });
  }
});


router.post("/link-wallet", auth, async (req, res) => {
  try {
    if (String(req.user?.role || "").toLowerCase() !== "seller") {
      return res.status(403).json({ message: "Only seller can link wallet" });
    }

    const wallet = normalizeWallet(req.body.wallet_address);
    if (!wallet) return res.status(400).json({ message: "Invalid wallet_address" });

    const u = await pool.query("SELECT approval_status FROM users WHERE id=$1", [req.user.userId]);
    if (u.rowCount === 0) return res.status(404).json({ message: "User not found" });

    const st = String(u.rows[0].approval_status || "").toUpperCase();
    if (st !== "APPROVED") return res.status(403).json({ message: "Seller not approved yet", approval_status: st });

    await pool.query("UPDATE users SET wallet_address=$1 WHERE id=$2", [wallet, req.user.userId]);

    return res.status(200).json({ wallet_address: wallet });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/verify", auth, async (req, res) => {
  try {
    if (req.user.role !== "manufacturer") return res.status(403).json({ message: "Only manufacturer can verify sellers" });

    const wallet = normalizeWallet(req.body.wallet_address);
    if (!wallet) return res.status(400).json({ message: "Invalid wallet_address" });

    const tx = await contract.verifySeller(wallet);
    const receipt = await tx.wait();

    return res.status(200).json({ wallet_address: wallet, chain_tx_hash: receipt.hash });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/revoke", auth, async (req, res) => {
  try {
    if (req.user.role !== "manufacturer") return res.status(403).json({ message: "Only manufacturer can revoke sellers" });

    const wallet = normalizeWallet(req.body.wallet_address);
    if (!wallet) return res.status(400).json({ message: "Invalid wallet_address" });

    const tx = await contract.revokeSeller(wallet);
    const receipt = await tx.wait();

    return res.status(200).json({ wallet_address: wallet, chain_tx_hash: receipt.hash });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

module.exports = router;
