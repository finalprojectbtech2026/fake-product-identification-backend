const express = require("express");
const crypto = require("crypto");
const pool = require("../config/db");
const auth = require("../middleware/auth");

const router = express.Router();

const sha256 = (input) => crypto.createHash("sha256").update(String(input)).digest("hex");

const makeStateHash = ({ product_code, action, actor_id, prev_hash, extra }) => {
  return sha256(
    JSON.stringify({
      product_code,
      action,
      actor_id,
      prev_hash: prev_hash || "",
      extra: extra || {},
      ts: Date.now()
    })
  );
};

const makeQrPayload = ({ product_code, state_hash }) => {
  return JSON.stringify({
    productId: product_code,
    stateHash: state_hash
  });
};

router.post("/", auth, async (req, res) => {
  try {
    if (req.user.role !== "manufacturer") {
      return res.status(403).json({ message: "Only manufacturer can register product" });
    }

    const product_code = String(req.body.product_code || "").trim();
    const name = String(req.body.name || "").trim();
    const batch = req.body.batch ? String(req.body.batch).trim() : null;
    const meta_json = req.body.meta_json && typeof req.body.meta_json === "object" ? req.body.meta_json : {};
    const ipfs_cid = req.body.ipfs_cid ? String(req.body.ipfs_cid).trim() : null;

    if (!product_code || !name) return res.status(400).json({ message: "Missing product_code or name" });

    const exists = await pool.query("SELECT id FROM products WHERE product_code=$1", [product_code]);
    if (exists.rowCount > 0) return res.status(409).json({ message: "product_code already exists" });

    const current_state_hash = makeStateHash({
      product_code,
      action: "REGISTER",
      actor_id: req.user.userId,
      prev_hash: "",
      extra: { name, batch, meta_json, ipfs_cid }
    });

    const created = await pool.query(
      `INSERT INTO products(product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id, product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash, created_at`,
      [product_code, req.user.userId, name, batch, meta_json, ipfs_cid, current_state_hash]
    );

    const product = created.rows[0];

    await pool.query(
      `INSERT INTO product_events(product_id, event_type, actor_id, prev_state_hash, new_state_hash, chain_tx_hash, notes)
       VALUES($1,'REGISTER',$2,$3,$4,$5,$6)`,
      [product.id, req.user.userId, null, current_state_hash, null, "Product registered"]
    );

    const qr_payload = makeQrPayload({ product_code, state_hash: current_state_hash });

    await pool.query(
      `INSERT INTO qr_codes(product_id, qr_payload, last_state_hash)
       VALUES($1,$2,$3)`,
      [product.id, qr_payload, current_state_hash]
    );

    return res.status(201).json({ product, qr: { product_id: product.id, qr_payload, last_state_hash: current_state_hash } });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/:productCode/transfer", auth, async (req, res) => {
  try {
    if (req.user.role !== "seller") return res.status(403).json({ message: "Only seller can transfer/update" });

    const productCode = String(req.params.productCode || "").trim();
    const notes = req.body.notes ? String(req.body.notes).trim() : "Transferred/Updated";
    const extra = req.body.extra && typeof req.body.extra === "object" ? req.body.extra : {};

    const p = await pool.query("SELECT id, product_code, current_state_hash FROM products WHERE product_code=$1", [productCode]);
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];
    const prev_hash = product.current_state_hash;

    const new_hash = makeStateHash({
      product_code: product.product_code,
      action: "TRANSFER",
      actor_id: req.user.userId,
      prev_hash,
      extra
    });

    await pool.query("UPDATE products SET current_state_hash=$1 WHERE id=$2", [new_hash, product.id]);

    await pool.query(
      `INSERT INTO product_events(product_id, event_type, actor_id, prev_state_hash, new_state_hash, chain_tx_hash, notes)
       VALUES($1,'TRANSFER',$2,$3,$4,$5,$6)`,
      [product.id, req.user.userId, prev_hash, new_hash, null, notes]
    );

    const qr_payload = makeQrPayload({ product_code: product.product_code, state_hash: new_hash });

    await pool.query(
      `INSERT INTO qr_codes(product_id, qr_payload, last_state_hash)
       VALUES($1,$2,$3)
       ON CONFLICT (product_id)
       DO UPDATE SET qr_payload=EXCLUDED.qr_payload, last_state_hash=EXCLUDED.last_state_hash, updated_at=now()`,
      [product.id, qr_payload, new_hash]
    );

    return res.status(200).json({
      product_code: product.product_code,
      prev_state_hash: prev_hash,
      new_state_hash: new_hash,
      qr_payload
    });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

router.get("/:productCode/history", async (req, res) => {
  try {
    const productCode = String(req.params.productCode || "").trim();

    const p = await pool.query(
      `SELECT id, product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash, created_at
       FROM products
       WHERE product_code=$1`,
      [productCode]
    );
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];

    const events = await pool.query(
      `SELECT e.id, e.event_type, e.actor_id, e.prev_state_hash, e.new_state_hash, e.chain_tx_hash, e.notes, e.created_at,
              u.role as actor_role, u.email as actor_email
       FROM product_events e
       JOIN users u ON u.id = e.actor_id
       WHERE e.product_id=$1
       ORDER BY e.created_at ASC`,
      [product.id]
    );

    const qr = await pool.query(
      `SELECT qr_payload, last_state_hash, updated_at
       FROM qr_codes
       WHERE product_id=$1`,
      [product.id]
    );

    return res.status(200).json({
      product,
      qr: qr.rowCount ? qr.rows[0] : null,
      events: events.rows
    });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

router.post("/scan", async (req, res) => {
  try {
    const productId = String(req.body.productId || "").trim();
    const stateHash = String(req.body.stateHash || "").trim();

    if (!productId || !stateHash) return res.status(400).json({ message: "Missing productId/stateHash" });

    const p = await pool.query(
      `SELECT id, product_code, name, batch, meta_json, ipfs_cid, current_state_hash, created_at
       FROM products
       WHERE product_code=$1`,
      [productId]
    );
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];

    const isOriginal = product.current_state_hash === stateHash;

    const events = await pool.query(
      `SELECT e.id, e.event_type, e.actor_id, e.prev_state_hash, e.new_state_hash, e.chain_tx_hash, e.notes, e.created_at,
              u.role as actor_role, u.email as actor_email
       FROM product_events e
       JOIN users u ON u.id = e.actor_id
       WHERE e.product_id=$1
       ORDER BY e.created_at ASC`,
      [product.id]
    );

    return res.status(200).json({
      product: {
        product_code: product.product_code,
        name: product.name,
        batch: product.batch,
        meta_json: product.meta_json,
        ipfs_cid: product.ipfs_cid,
        current_state_hash: product.current_state_hash,
        created_at: product.created_at
      },
      scanned: { productId, stateHash },
      verdict: {
        isOriginal,
        message: isOriginal ? "Original (latest state matches)" : "Mismatch (old QR or duplicate risk)"
      },
      events: events.rows
    });
  } catch {
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
