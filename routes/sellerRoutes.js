const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { contract, ethers } = require("../config/blockchain");

const router = express.Router();

const normalizeWallet = (w) => {
  const v = String(w || "").trim();
  if (!v) return "";
  return ethers.getAddress(v);
};

router.post("/link-wallet", auth, async (req, res) => {
  try {
    const wallet = normalizeWallet(req.body.wallet_address);
    if (!wallet) return res.status(400).json({ message: "Missing wallet_address" });

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
    if (!wallet) return res.status(400).json({ message: "Missing wallet_address" });

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
    if (!wallet) return res.status(400).json({ message: "Missing wallet_address" });

    const tx = await contract.revokeSeller(wallet);
    const receipt = await tx.wait();

    return res.status(200).json({ wallet_address: wallet, chain_tx_hash: receipt.hash });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

module.exports = router;