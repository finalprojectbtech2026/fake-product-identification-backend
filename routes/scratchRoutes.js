const express = require("express");
const router = express.Router();
const scratchController = require("../controllers/scratchController");

router.post("/save-entry", scratchController.saveEntry);
router.get("/entries", scratchController.getAllEntries);
router.post("/check-customer", scratchController.checkCustomer);

module.exports = router;
