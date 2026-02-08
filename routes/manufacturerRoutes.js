const express = require("express");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

const isRegulator = (req) => String(req.user?.role || "").toLowerCase() === "regulator";

router.get("/", auth, async (req, res) => {
  try {
    if (!isRegulator(req)) return res.status(403).json({ message: "Forbidden" });

    const status = String(req.query.status || "").trim().toUpperCase();
    const allowed = new Set(["PENDING", "APPROVED", "REJECTED"]);

    const where = [];
    const params = [];

    where.push("role='manufacturer'");

    if (status) {
      if (!allowed.has(status)) return res.status(400).json({ message: "Invalid status" });
      params.push(status);
      where.push(`approval_status=$${params.length}`);
    }

    const q = await pool.query(
      `
      SELECT id, role, email, wallet_address, approval_status, approval_notes,
             approved_by, approved_at, rejected_by, rejected_at, created_at
      FROM users
      WHERE ${where.join(" AND ")}
      ORDER BY created_at DESC
      `,
      params
    );

    return res.status(200).json({ manufacturers: q.rows });
  } catch (err) {
    console.error("MANUFACTURERS_LIST_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

router.get("/:id", auth, async (req, res) => {
  try {
    if (!isRegulator(req)) return res.status(403).json({ message: "Forbidden" });

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ message: "Missing id" });

    const q = await pool.query(
      `
      SELECT id, role, email, wallet_address, approval_status, approval_notes,
             approved_by, approved_at, rejected_by, rejected_at, created_at
      FROM users
      WHERE id=$1 AND role='manufacturer'
      `,
      [id]
    );

    if (q.rowCount === 0) return res.status(404).json({ message: "Manufacturer not found" });
    return res.status(200).json({ manufacturer: q.rows[0] });
  } catch (err) {
    console.error("MANUFACTURER_GET_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

router.post("/:id/approve", auth, async (req, res) => {
  try {
    if (!isRegulator(req)) return res.status(403).json({ message: "Forbidden" });

    const id = String(req.params.id || "").trim();
    const notes = String(req.body?.notes || "").trim() || null;
    if (!id) return res.status(400).json({ message: "Missing id" });

    const q = await pool.query(
      `
      UPDATE users
      SET approval_status='APPROVED',
          approval_notes=$2,
          approved_by=$3,
          approved_at=NOW(),
          rejected_by=NULL,
          rejected_at=NULL
      WHERE id=$1 AND role='manufacturer'
      RETURNING id, role, email, wallet_address, approval_status, approval_notes,
                approved_by, approved_at, rejected_by, rejected_at, created_at
      `,
      [id, notes, req.user.userId]
    );

    if (q.rowCount === 0) return res.status(404).json({ message: "Manufacturer not found" });
    return res.status(200).json({ manufacturer: q.rows[0] });
  } catch (err) {
    console.error("MANUFACTURER_APPROVE_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

router.post("/:id/reject", auth, async (req, res) => {
  try {
    if (!isRegulator(req)) return res.status(403).json({ message: "Forbidden" });

    const id = String(req.params.id || "").trim();
    const notes = String(req.body?.notes || "").trim() || null;
    if (!id) return res.status(400).json({ message: "Missing id" });

    const q = await pool.query(
      `
      UPDATE users
      SET approval_status='REJECTED',
          approval_notes=$2,
          rejected_by=$3,
          rejected_at=NOW(),
          approved_by=NULL,
          approved_at=NULL
      WHERE id=$1 AND role='manufacturer'
      RETURNING id, role, email, wallet_address, approval_status, approval_notes,
                approved_by, approved_at, rejected_by, rejected_at, created_at
      `,
      [id, notes, req.user.userId]
    );

    if (q.rowCount === 0) return res.status(404).json({ message: "Manufacturer not found" });
    return res.status(200).json({ manufacturer: q.rows[0] });
  } catch (err) {
    console.error("MANUFACTURER_REJECT_ERROR:", err);
    return res.status(500).json({ message: "Server error", error: String(err?.message || err) });
  }
});

module.exports = router;
