const express = require('express');
const jwt = require('jsonwebtoken');
const Session = require('../models/Session'); // ✅ Use Session model instead
const router = express.Router();

router.post('/refresh-token', async (req, res) => {
    try {
        const refreshToken = req.cookies?.refreshToken; // ✅ Safe check for cookies

        if (!refreshToken) {
            return res.status(401).json({ error: '⚠️ Missing refresh token!' });
        }

        const existingSession = await Session.findOne({ refreshToken, canceled: false });

        if (!existingSession) {
            return res.status(403).json({ error: '⚠️ Invalid or expired session!' });
        }

        // Verify refresh token
        try {
            const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

            // Generate a new access token
            const newAccessToken = jwt.sign(
                { userId: decoded.userId, userType: decoded.userType },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );

            return res.status(200).json({ accessToken: newAccessToken });
        } catch (err) {
            await Session.deleteOne({ refreshToken }); // ✅ Remove invalid tokens
            return res.status(403).json({ error: '⚠️ Invalid or expired refresh token!' });
        }
    } catch (error) {
        console.error("❌ Refresh Token Error:", error);
        return res.status(500).json({ error: '⚠️ Internal server error' });
    }
});

module.exports = router;
