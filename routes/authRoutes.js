// D:\fpi\backend\routes\authRoutes.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

const allowedRoles = new Set(["manufacturer", "seller", "customer", "regulator"]);

const needsApproval = (role) => {
  const r = String(role || "").trim().toLowerCase();
  return r === "manufacturer" || r === "seller";
};

router.post("/signup", async (req, res) => {
  try {
    const role = String(req.body.role || "").trim().toLowerCase();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!allowedRoles.has(role)) return res.status(400).json({ message: "Invalid role" });
    if (!email || !email.includes("@")) return res.status(400).json({ message: "Invalid email" });
    if (!password || password.length < 4) return res.status(400).json({ message: "Password too short" });

    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rowCount > 0) return res.status(409).json({ message: "Email already exists" });

    const password_hash = await bcrypt.hash(password, 10);
    const approval_status = needsApproval(role) ? "PENDING" : "APPROVED";

    const created = await pool.query(
      "INSERT INTO users(role,email,password_hash,approval_status) VALUES($1,$2,$3,$4) RETURNING id, role, email, wallet_address, approval_status, created_at",
      [role, email, password_hash, approval_status]
    );

    const user = created.rows[0];

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ message: "JWT secret missing" });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
        email: user.email,
        wallet_address: user.wallet_address || null,
        approval_status: user.approval_status
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({ token, user });
  } catch (err) {
    console.error("SIGNUP_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const found = await pool.query(
      "SELECT id, role, email, password_hash, wallet_address, approval_status FROM users WHERE email=$1",
      [email]
    );
    if (found.rowCount === 0) return res.status(401).json({ message: "Invalid credentials" });

    const user = found.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const role = String(user.role || "").toLowerCase();
    const st = String(user.approval_status || "").toUpperCase();

    if (needsApproval(role) && st !== "APPROVED") {
      return res.status(403).json({
        message: `${role === "seller" ? "Seller" : "Manufacturer"} not approved yet`,
        approval_status: user.approval_status
      });
    }

    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ message: "JWT secret missing" });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        role: user.role,
        email: user.email,
        wallet_address: user.wallet_address || null,
        approval_status: user.approval_status
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      token,
      user: {
        id: user.id,
        role: user.role,
        email: user.email,
        wallet_address: user.wallet_address || null,
        approval_status: user.approval_status
      }
    });
  } catch (err) {
    console.error("LOGIN_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    const q = await pool.query(
      "SELECT id, role, email, wallet_address, approval_status, created_at FROM users WHERE id=$1",
      [req.user.userId]
    );
    if (q.rowCount === 0) return res.status(404).json({ message: "User not found" });
    return res.status(200).json({ user: q.rows[0] });
  } catch (err) {
    console.error("ME_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

module.exports = router;
