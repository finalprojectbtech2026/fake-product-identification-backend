const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

const allowedRoles = new Set(["manufacturer", "seller", "customer", "regulator"]);

const norm = (v) => String(v || "").trim();
const normLower = (v) => norm(v).toLowerCase();

const needsApproval = (role) => {
  const r = normLower(role);
  return r === "manufacturer" || r === "seller";
};

const needsExtraDetails = (role) => {
  const r = normLower(role);
  return r === "manufacturer" || r === "seller";
};

router.post("/signup", async (req, res) => {
  try {
    const role = normLower(req.body.role);
    const email = normLower(req.body.email);
    const password = String(req.body.password || "");

    const name = norm(req.body.name);
    const company_name = norm(req.body.company_name);
    const address = norm(req.body.address);
    const license_number = norm(req.body.license_number);

    if (!allowedRoles.has(role)) return res.status(400).json({ message: "Invalid role" });
    if (!email || !email.includes("@")) return res.status(400).json({ message: "Invalid email" });
    if (!password || password.length < 4) return res.status(400).json({ message: "Password too short" });

    if (needsExtraDetails(role)) {
      if (!name) return res.status(400).json({ message: "Name is required" });
      if (!company_name) return res.status(400).json({ message: "Company name is required" });
      if (!address) return res.status(400).json({ message: "Address is required" });
      if (!license_number) return res.status(400).json({ message: "Licence number is required" });
    }

    const exists = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rowCount > 0) return res.status(409).json({ message: "Email already exists" });

    const password_hash = await bcrypt.hash(password, 10);
    const approval_status = needsApproval(role) ? "PENDING" : "APPROVED";

    const created = await pool.query(
      `
      INSERT INTO users(role, name, company_name, email, address, license_number, password_hash, approval_status)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)
      RETURNING id, role, name, company_name, email, address, license_number, wallet_address, approval_status, created_at
      `,
      [
        role,
        needsExtraDetails(role) ? name : null,
        needsExtraDetails(role) ? company_name : null,
        email,
        needsExtraDetails(role) ? address : null,
        needsExtraDetails(role) ? license_number : null,
        password_hash,
        approval_status
      ]
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
    const email = normLower(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) return res.status(400).json({ message: "Missing fields" });

    const found = await pool.query(
      "SELECT id, role, name, company_name, email, address, license_number, password_hash, wallet_address, approval_status FROM users WHERE email=$1",
      [email]
    );
    if (found.rowCount === 0) return res.status(401).json({ message: "Invalid credentials" });

    const user = found.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const role = normLower(user.role);
    const st = String(user.approval_status || "").toUpperCase().trim();

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
        name: user.name || null,
        company_name: user.company_name || null,
        email: user.email,
        address: user.address || null,
        license_number: user.license_number || null,
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
      "SELECT id, role, name, company_name, email, address, license_number, wallet_address, approval_status, created_at FROM users WHERE id=$1",
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
