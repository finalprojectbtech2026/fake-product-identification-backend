const express = require("express");
const pool = require("../config/db");

const router = express.Router();

const normalize = (v) => String(v || "").trim();

router.post("/", async (req, res) => {
  try {
    const productCode = normalize(req.body.product_code);
    const stateHash = normalize(req.body.state_hash);

    const customer_name = normalize(req.body.customer_name);
    const customer_phone = normalize(req.body.customer_phone);
    const customer_email = normalize(req.body.customer_email);
    const customer_address = normalize(req.body.customer_address);

    const payment_method = normalize(req.body.payment_method).toUpperCase();

    if (!productCode || !stateHash) return res.status(400).json({ message: "Missing product_code/state_hash" });
    if (!customer_name || !customer_phone || !customer_address) return res.status(400).json({ message: "Missing customer details" });
    if (!["COD", "MOCK_UPI", "MOCK_CARD"].includes(payment_method)) return res.status(400).json({ message: "Invalid payment_method" });

    const p = await pool.query(
      `SELECT id, product_code, current_state_hash, sale_status
       FROM products
       WHERE product_code=$1`,
      [productCode]
    );

    if (p.rowCount === 0) return res.status(404).json({ message: "Product not found" });

    const product = p.rows[0];

    if (String(product.sale_status || "").toUpperCase() === "SOLD") {
      return res.status(409).json({ message: "Product already sold" });
    }

    const isLatestDbState = product.current_state_hash === stateHash;
    if (!isLatestDbState) {
      return res.status(409).json({ message: "Old QR detected. Please scan latest QR." });
    }

    const payment_status = payment_method === "COD" ? "PENDING" : "PAID";
    const order_status = "CONFIRMED";

    const created = await pool.query(
      `INSERT INTO orders(product_id, product_code, state_hash, customer_name, customer_phone, customer_email, customer_address, payment_method, payment_status, order_status)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id, created_at, payment_status, order_status`,
      [
        product.id,
        product.product_code,
        stateHash,
        customer_name,
        customer_phone,
        customer_email || null,
        customer_address,
        payment_method,
        payment_status,
        order_status
      ]
    );

    const order = created.rows[0];

    await pool.query(
      `UPDATE products
       SET sale_status='SOLD', sold_at=now(), sold_order_id=$1
       WHERE id=$2`,
      [order.id, product.id]
    );

    return res.status(201).json({
      ok: true,
      message: "Purchase successful",
      order: { ...order, product_code: product.product_code }
    });
  } catch (e) {
    return res.status(500).json({ message: "Server error", error: String(e?.message || e) });
  }
});

module.exports = router;
