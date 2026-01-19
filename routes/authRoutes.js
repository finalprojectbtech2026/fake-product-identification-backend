const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

router.post("/signup", async (req, res) => {
  try {
    const role = String(req.body.role || "").trim().toLowerCase();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!["manufacturer", "seller", "customer"].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }
    if (!email || !email.includes("@")) {
      return res.status(400).json({ message: "Invalid email" });
    }
    if (!password || password.length < 4) {
      return res.status(400).json({ message: "Password too short" });
    }

    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rowCount > 0) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const created = await pool.query(
      "INSERT INTO users(role,email,password_hash) VALUES($1,$2,$3) RETURNING id, role, email, created_at",
      [role, email, password_hash]
    );

    const user = created.rows[0];
    const token = jwt.sign(
      { userId: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(201).json({ token, user });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const found = await pool.query("SELECT id, role, email, password_hash FROM users WHERE email=$1", [email]);
    if (found.rowCount === 0) return res.status(401).json({ message: "Invalid credentials" });

    const user = found.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      token,
      user: { id: user.id, role: user.role, email: user.email }
    });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/me", auth, async (req, res) => {
  try {
    const q = await pool.query("SELECT id, role, email, created_at FROM users WHERE id=$1", [req.user.userId]);
    if (q.rowCount === 0) return res.status(404).json({ message: "User not found" });
    return res.status(200).json({ user: q.rows[0] });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
