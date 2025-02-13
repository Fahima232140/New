const express = require("express");
const Session = require("../models/Session"); // ✅ Ensure correct path
const router = express.Router();

router.post("/logout", async (req, res) => {
    try {
        const { deviceId } = req.body;
        const userId = req.user?.id; // Assuming authentication middleware adds req.user

        if (!userId) {
            return res.status(401).json({ error: "⚠️ Unauthorized request!" });
        }

        if (!deviceId) {
            return res.status(400).json({ error: "⚠️ Missing device ID!" });
        }

        // ✅ Ensure only the user's own session is removed
        const deletedSession = await Session.deleteOne({ userId, deviceId });

        if (deletedSession.deletedCount === 0) {
            return res.status(404).json({ error: "⚠️ Session not found!" });
        }

        // 🔐 Clear HTTP-only refreshToken cookie
        res.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "Strict" });

        return res.status(204).end(); // ✅ No content response (best practice)

    } catch (error) {
        console.error("❌ Logout Error:", error);
        return res.status(500).json({ error: "⚠️ Server error. Please try again." });
    }
});

module.exports = router;
