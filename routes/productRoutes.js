const express = require("express");
const crypto = require("crypto");
const pool = require("../config/db");
const auth = require("../middleware/auth");
const { contract, ethers } = require("../config/blockchain");
const { canonicalJson } = require("../utils/canonicalJson");
const { sha256Hex, sha256Bytes32 } = require("../utils/hash");

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

const normalizeWallet = (w) => {
  const v = String(w || "").trim();
  if (!v) return "";
  try {
    return ethers.getAddress(v);
  } catch {
    return "";
  }
};

const ensureAuditTable = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS product_audits (
      product_id uuid PRIMARY KEY REFERENCES products(id) ON DELETE CASCADE,
      decision text NOT NULL CHECK (decision IN ('ACCEPT','REJECT')),
      notes text,
      regulator_id uuid REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    )
  `);
};

const resolveEventsTable = async () => {
  const r = await pool.query(
    `
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema='public' AND table_name IN ('product_events','products_events')
    ORDER BY CASE WHEN table_name='product_events' THEN 1 ELSE 2 END
    LIMIT 1
    `
  );
  return r.rowCount ? r.rows[0].table_name : "product_events";
};

const getSellerWalletAndStatus = async (userId) => {
  const q = await pool.query("SELECT wallet_address, approval_status FROM users WHERE id=$1", [userId]);
  if (q.rowCount === 0) return { wallet: "", approval: "" };
  const wallet = q.rows[0].wallet_address ? normalizeWallet(q.rows[0].wallet_address) : "";
  const approval = String(q.rows[0].approval_status || "").toUpperCase();
  return { wallet, approval };
};

const listSellerProducts = async (sellerWallet) => {
  const q = await pool.query(
    `
    SELECT id, product_code, current_state_hash, created_at
    FROM products
    ORDER BY created_at DESC
    LIMIT 500
    `
  );

  const rows = q.rows || [];
  const out = [];

  for (const p of rows) {
    try {
      const onchain = await contract.getProduct(p.product_code);
      const exists = Boolean(onchain[0]);
      if (!exists) continue;

      const owner = normalizeWallet(onchain[2]);
      if (!owner) continue;

      if (owner.toLowerCase() !== sellerWallet.toLowerCase()) continue;

      out.push({
        product_code: p.product_code,
        status: "OWNED",
        owner_wallet: owner,
        latest_state_hash: p.current_state_hash || ""
      });
    } catch {
      continue;
    }
  }

  return out;
};

router.get("/", auth, async (req, res) => {
  try {
    const role = String(req.user?.role || "").toLowerCase();

    if (role === "regulator") {
      await ensureAuditTable();

      const q = await pool.query(
        `
        SELECT
          p.id,
          p.product_code,
          p.manufacturer_id,
          p.name,
          p.batch,
          p.meta_json,
          p.ipfs_cid,
          p.current_state_hash,
          p.cloud_hash,
          p.nfc_uid_hash,
          p.chain_register_tx_hash,
          p.created_at,
          a.decision AS audit_status,
          a.notes AS audit_notes,
          a.updated_at AS audit_at,
          u.email AS audit_by_email
        FROM products p
        LEFT JOIN product_audits a ON a.product_id = p.id
        LEFT JOIN users u ON u.id = a.regulator_id
        ORDER BY p.created_at DESC
        `
      );

      return res.status(200).json({ products: q.rows });
    }

    if (role === "seller") {
      const { wallet, approval } = await getSellerWalletAndStatus(req.user.userId);
      if (approval !== "APPROVED") return res.status(403).json({ message: "Seller not approved yet", approval_status: approval });
      if (!wallet) return res.status(400).json({ message: "Seller wallet not linked" });

      const products = await listSellerProducts(wallet);
      return res.status(200).json({ products });
    }

    return res.status(403).json({ message: "Not allowed" });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.get("/mine", auth, async (req, res) => {
  try {
    const role = String(req.user?.role || "").toLowerCase();

    if (role === "manufacturer") {
      await ensureAuditTable();

      const q = await pool.query(
        `
        SELECT
          p.id,
          p.product_code,
          p.manufacturer_id,
          p.name,
          p.batch,
          p.meta_json,
          p.ipfs_cid,
          p.current_state_hash,
          p.cloud_hash,
          p.nfc_uid_hash,
          p.chain_register_tx_hash,
          p.created_at,
          a.decision AS audit_status,
          a.notes AS audit_notes,
          a.updated_at AS audit_at,
          u.email AS audit_by_email
        FROM products p
        LEFT JOIN product_audits a ON a.product_id = p.id
        LEFT JOIN users u ON u.id = a.regulator_id
        WHERE p.manufacturer_id=$1
        ORDER BY p.created_at DESC
        `,
        [req.user.userId]
      );

      return res.status(200).json({ products: q.rows });
    }

    if (role === "seller") {
      const { wallet, approval } = await getSellerWalletAndStatus(req.user.userId);
      if (approval !== "APPROVED") return res.status(403).json({ message: "Seller not approved yet", approval_status: approval });
      if (!wallet) return res.status(400).json({ message: "Seller wallet not linked" });

      const products = await listSellerProducts(wallet);
      return res.status(200).json({ products });
    }

    return res.status(403).json({ message: "Only manufacturer or seller can view own products" });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/:productCode/audit", auth, async (req, res) => {
  try {
    if (req.user.role !== "regulator") return res.status(403).json({ message: "Only regulator can audit products" });

    await ensureAuditTable();

    const productCode = String(req.params.productCode || "").trim();
    const decision = String(req.body.decision || "").trim().toUpperCase();
    const notes = req.body.notes ? String(req.body.notes).trim() : null;

    if (!productCode) return res.status(400).json({ message: "Missing productCode" });
    if (!["ACCEPT", "REJECT"].includes(decision)) return res.status(400).json({ message: "decision must be ACCEPT or REJECT" });

    const p = await pool.query("SELECT id, product_code FROM products WHERE product_code=$1", [productCode]);
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];

    await pool.query(
      `
      INSERT INTO product_audits(product_id, decision, notes, regulator_id)
      VALUES($1,$2,$3,$4)
      ON CONFLICT (product_id)
      DO UPDATE SET decision=EXCLUDED.decision, notes=EXCLUDED.notes, regulator_id=EXCLUDED.regulator_id, updated_at=now()
      `,
      [product.id, decision, notes, req.user.userId]
    );

    return res.status(200).json({
      product_code: product.product_code,
      decision,
      notes: notes || (decision === "ACCEPT" ? "Accepted as original by regulator" : "Rejected as duplicate by regulator")
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/", auth, async (req, res) => {
  try {
    if (req.user.role !== "manufacturer") return res.status(403).json({ message: "Only manufacturer can register product" });

    const product_code = String(req.body.product_code || "").trim();
    const name = String(req.body.name || "").trim();
    const batch = req.body.batch ? String(req.body.batch).trim() : null;
    const meta_json = req.body.meta_json && typeof req.body.meta_json === "object" ? req.body.meta_json : {};
    const ipfs_cid = req.body.ipfs_cid ? String(req.body.ipfs_cid).trim() : null;

    const nfc_uid = req.body.nfc_uid ? String(req.body.nfc_uid).trim() : "";
    const nfc_uid_hash = nfc_uid ? sha256Hex(nfc_uid) : null;
    const nfc_uid_hash_bytes32 = nfc_uid ? sha256Bytes32(nfc_uid) : sha256Bytes32("");

    if (!product_code || !name) return res.status(400).json({ message: "Missing product_code or name" });

    const exists = await pool.query("SELECT id FROM products WHERE product_code=$1", [product_code]);
    if (exists.rowCount > 0) return res.status(409).json({ message: "product_code already exists" });

    const cloudPayload = canonicalJson({ product_code, name, batch, meta_json, ipfs_cid });
    const cloud_hash = sha256Hex(cloudPayload);
    const cloud_hash_bytes32 = sha256Bytes32(cloudPayload);

    const tx = await contract.registerProduct(product_code, cloud_hash_bytes32, nfc_uid_hash_bytes32);
    const receipt = await tx.wait();

    const current_state_hash = makeStateHash({
      product_code,
      action: "REGISTER",
      actor_id: req.user.userId,
      prev_hash: "",
      extra: { name, batch, meta_json, ipfs_cid, cloud_hash, nfc_uid_hash, chain_register_tx_hash: receipt.hash }
    });

    const created = await pool.query(
      `INSERT INTO products(product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash, cloud_hash, nfc_uid_hash, chain_register_tx_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id, product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash, cloud_hash, nfc_uid_hash, chain_register_tx_hash, created_at`,
      [product_code, req.user.userId, name, batch, meta_json, ipfs_cid, current_state_hash, cloud_hash, nfc_uid_hash, receipt.hash]
    );

    const product = created.rows[0];
    const eventsTable = await resolveEventsTable();

    await pool.query(
      `INSERT INTO ${eventsTable}(product_id, event_type, actor_id, prev_state_hash, new_state_hash, chain_tx_hash, notes)
       VALUES($1,'REGISTER',$2,$3,$4,$5,$6)`,
      [product.id, req.user.userId, null, current_state_hash, receipt.hash, "Product registered on-chain"]
    );

    const qr_payload = makeQrPayload({ product_code, state_hash: current_state_hash });

    await pool.query(
      `INSERT INTO qr_codes(product_id, qr_payload, last_state_hash)
       VALUES($1,$2,$3)`,
      [product.id, qr_payload, current_state_hash]
    );

    return res.status(201).json({
      product,
      chain: { contract_address: process.env.CONTRACT_ADDRESS, register_tx_hash: receipt.hash, cloud_hash, nfc_uid_hash },
      qr: { product_id: product.id, qr_payload, last_state_hash: current_state_hash }
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/:productCode/transfer", auth, async (req, res) => {
  try {
    if (String(req.user?.role || "").toLowerCase() !== "seller") {
      return res.status(403).json({ message: "Only seller can transfer/update" });
    }

    const { wallet: sellerWallet, approval } = await getSellerWalletAndStatus(req.user.userId);
    if (approval !== "APPROVED") return res.status(403).json({ message: "Seller not approved yet", approval_status: approval });
    if (!sellerWallet) return res.status(400).json({ message: "Link your wallet first" });

    const productCode = String(req.params.productCode || "").trim();
    const notes = req.body.notes ? String(req.body.notes).trim() : "Transferred/Updated";
    const extra = req.body.extra && typeof req.body.extra === "object" ? req.body.extra : {};
    const toWallet = normalizeWallet(req.body.to_wallet);

    if (!toWallet) return res.status(400).json({ message: "Invalid to_wallet" });

    const p = await pool.query("SELECT id, product_code, current_state_hash FROM products WHERE product_code=$1", [productCode]);
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];
    const prev_hash = product.current_state_hash;

    let chainOwner = "";
    try {
      const onchain = await contract.getProduct(product.product_code);
      const exists = Boolean(onchain[0]);
      if (!exists) return res.status(404).json({ message: "On-chain product not found" });
      chainOwner = normalizeWallet(onchain[2]);
    } catch {
      return res.status(500).json({ message: "Unable to read on-chain product" });
    }

    if (!chainOwner || chainOwner.toLowerCase() !== sellerWallet.toLowerCase()) {
      return res.status(403).json({ message: "You are not the current on-chain owner of this product" });
    }

    const tx = await contract.transferProduct(product.product_code, toWallet);
    const receipt = await tx.wait();

    const new_hash = makeStateHash({
      product_code: product.product_code,
      action: "TRANSFER",
      actor_id: req.user.userId,
      prev_hash,
      extra: { ...extra, from_wallet: sellerWallet, to_wallet: toWallet, chain_transfer_tx_hash: receipt.hash }
    });

    await pool.query("UPDATE products SET current_state_hash=$1 WHERE id=$2", [new_hash, product.id]);

    const eventsTable = await resolveEventsTable();

    await pool.query(
      `INSERT INTO ${eventsTable}(product_id, event_type, actor_id, prev_state_hash, new_state_hash, chain_tx_hash, notes)
       VALUES($1,'TRANSFER',$2,$3,$4,$5,$6)`,
      [product.id, req.user.userId, prev_hash, new_hash, receipt.hash, notes]
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
      to_wallet: toWallet,
      chain_transfer_tx_hash: receipt.hash,
      qr_payload
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.get("/:productCode/history", async (req, res) => {
  try {
    const productCode = String(req.params.productCode || "").trim();

    const p = await pool.query(
      `SELECT id, product_code, manufacturer_id, name, batch, meta_json, ipfs_cid, current_state_hash, cloud_hash, nfc_uid_hash, chain_register_tx_hash, created_at
       FROM products
       WHERE product_code=$1`,
      [productCode]
    );
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];
    const eventsTable = await resolveEventsTable();

    const eventsQ = await pool.query(
      `SELECT e.id, e.event_type, e.actor_id, e.prev_state_hash, e.new_state_hash, e.chain_tx_hash, e.notes, e.created_at,
              u.role as actor_role, u.email as actor_email
       FROM ${eventsTable} e
       JOIN users u ON u.id = e.actor_id
       WHERE e.product_id=$1
       ORDER BY e.created_at ASC`,
      [product.id]
    );

    const events = (eventsQ.rows || []).map((ev) => ({
      id: ev.id,
      timestamp: ev.created_at,
      action: ev.event_type,
      from_wallet: "",
      to_wallet: "",
      state_hash: ev.new_state_hash || "",
      prev_state_hash: ev.prev_state_hash || "",
      new_state_hash: ev.new_state_hash || "",
      chain_tx_hash: ev.chain_tx_hash || "",
      notes: ev.notes || "",
      actor_role: ev.actor_role || "",
      actor_email: ev.actor_email || ""
    }));

    const qr = await pool.query(
      `SELECT qr_payload, last_state_hash, updated_at
       FROM qr_codes
       WHERE product_id=$1`,
      [product.id]
    );

    let chain = null;
    try {
      const onchain = await contract.getProduct(product.product_code);
      chain = {
        exists: onchain[0],
        manufacturer: onchain[1],
        currentOwner: onchain[2],
        cloudHash: onchain[3],
        nfcUidHash: onchain[4]
      };
    } catch {
      chain = null;
    }

    return res.status(200).json({
      product,
      qr: qr.rowCount ? qr.rows[0] : null,
      events,
      chain
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

router.post("/scan", async (req, res) => {
  try {
    const productId = String(req.body.productId || "").trim();
    const stateHash = String(req.body.stateHash || "").trim();

    if (!productId || !stateHash) return res.status(400).json({ message: "Missing productId/stateHash" });

    await ensureAuditTable();

    const p = await pool.query(
      `SELECT id, product_code, name, batch, meta_json, ipfs_cid, current_state_hash, cloud_hash, nfc_uid_hash, created_at
       FROM products
       WHERE product_code=$1`,
      [productId]
    );
    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];
    const isLatestDbState = product.current_state_hash === stateHash;

    const cloudPayload = canonicalJson({
      product_code: product.product_code,
      name: product.name,
      batch: product.batch,
      meta_json: product.meta_json,
      ipfs_cid: product.ipfs_cid
    });

    const recomputedCloudHashHex = sha256Hex(cloudPayload);
    const recomputedCloudHashBytes32 = sha256Bytes32(cloudPayload);

    const onchain = await contract.getProduct(product.product_code);

    const chainExists = onchain[0];
    const chainManufacturer = onchain[1];
    const chainOwner = onchain[2];
    const chainCloudHash = onchain[3];
    const chainNfcUidHash = onchain[4];

    const dbCloudHashMatches = (product.cloud_hash || "") === recomputedCloudHashHex;
    const chainCloudHashMatches = String(chainCloudHash).toLowerCase() === String(recomputedCloudHashBytes32).toLowerCase();

    const computedAuthentic = Boolean(chainExists && dbCloudHashMatches && chainCloudHashMatches);

    const a = await pool.query(`SELECT decision, notes, updated_at, regulator_id FROM product_audits WHERE product_id=$1`, [product.id]);
    const audit = a.rowCount ? a.rows[0] : null;

    const finalAuthentic = audit?.decision === "ACCEPT" ? true : audit?.decision === "REJECT" ? false : computedAuthentic;

    const eventsTable = await resolveEventsTable();

    const events = await pool.query(
      `SELECT e.id, e.event_type, e.actor_id, e.prev_state_hash, e.new_state_hash, e.chain_tx_hash, e.notes, e.created_at,
              u.role as actor_role, u.email as actor_email
       FROM ${eventsTable} e
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
        cloud_hash: product.cloud_hash,
        nfc_uid_hash: product.nfc_uid_hash,
        created_at: product.created_at
      },
      scanned: { productId, stateHash },
      chain: {
        exists: chainExists,
        manufacturer: chainManufacturer,
        currentOwner: chainOwner,
        cloudHash: chainCloudHash,
        nfcUidHash: chainNfcUidHash
      },
      audit: audit
        ? {
            decision: audit.decision,
            notes: audit.notes,
            updated_at: audit.updated_at,
            regulator_id: audit.regulator_id
          }
        : null,
      verdict: {
        isAuthentic: finalAuthentic,
        isLatestDbState,
        dbCloudHashMatches,
        chainCloudHashMatches,
        message:
          audit?.decision === "ACCEPT"
            ? "Accepted by regulator as original"
            : audit?.decision === "REJECT"
            ? "Rejected by regulator as duplicate"
            : computedAuthentic
            ? "Authentic (on-chain hash matches off-chain data)"
            : "Not authentic (hash mismatch or missing on-chain record)"
      },
      events: events.rows
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

module.exports = router;
