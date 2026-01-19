const pool = require("../config/db");

exports.saveEntry = async (req, res) => {
  const { name, mobile } = req.body;

  if (!name || !mobile) {
    return res.status(400).json({ error: "Name and mobile are required" });
  }

  try {
    const result = await pool.query(
      "INSERT INTO customers (name, mobile) VALUES ($1, $2) RETURNING *",
      [name.trim(), mobile.trim()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Mobile already exists" });
    }
    res.status(500).json({ error: err.message });
  }
};

exports.getAllEntries = async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM customers ORDER BY created_at DESC");
    res.status(200).json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.checkCustomer = async (req, res) => {
  const { mobile } = req.body;

  if (!mobile) {
    return res.status(400).json({ error: "Mobile is required" });
  }

  try {
    const result = await pool.query(
      "SELECT 1 FROM customers WHERE mobile = $1 LIMIT 1",
      [mobile.trim()]
    );
    res.json({ exists: result.rowCount > 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
