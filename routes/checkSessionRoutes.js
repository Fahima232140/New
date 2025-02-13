const express = require('express');
const jwt = require('jsonwebtoken');
const Session = require('../models/Session'); // ✅ Ensure correct path
const router = express.Router();

router.get('/check-session', async (req, res) => {
    try {
        const token = req.cookies.refreshToken; // Get refresh token from cookie
        if (!token) {
            return res.json({ valid: false });
        }

        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const session = await Session.findOne({ userId: decoded.userId, refreshToken: token });

        if (!session || session.canceled) {
            return res.json({ valid: false });
        }

        return res.json({ valid: true });

    } catch (error) {
        return res.json({ valid: false });
    }
});

module.exports = router;
