const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY); // Load Stripe Secret Key

exports.processPayment = async (req, res) => {
    try {
        const { amount, currency } = req.body; // Amount in cents, currency

        if (!amount || !currency) {
            return res.status(400).json({ error: "Amount and currency are required." });
        }

        // ✅ Create a PaymentIntent
        const paymentIntent = await stripe.paymentIntents.create({
            amount, // Amount in cents (e.g., $50.00 = 5000)
            currency, // e.g., "usd"
            payment_method_types: ["card"],
        });

        // Send `client_secret` to the frontend for Stripe.js to process the payment
        res.status(200).json({
            success: true,
            message: "Payment Intent created successfully.",
            clientSecret: paymentIntent.client_secret,
        });
    } catch (error) {
        console.error("Payment Error:", error);
        res.status(500).json({ error: "Payment processing failed." });
    }
};
