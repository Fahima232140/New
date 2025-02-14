const express = require("express");
const router = express.Router();
const { processPayment } = require("../controllers/paymentController");

// Define payment route
router.post('/process', async (req, res) => {
    try {
        const { amount, currency } = req.body;
        console.log(`Processing payment: ${amount} ${currency}`);

        // Simulating a successful payment response
        res.json({ success: true, message: "Payment processed successfully" });
    } catch (error) {
        console.error("Payment error:", error);
        res.status(500).json({ error: "Payment failed." });
    }
});


router.get("/", (req, res) => {
    res.status(200).json({ message: "Payment route is working!" });
});

module.exports = router;
