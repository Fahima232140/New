const jwt = require('jsonwebtoken');
const Session = require('../models/Session');

const authenticateJWT = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "⚠️ Unauthorized: No token provided" });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log(`🔎 Verifying token for user: ${decoded.userId}`);

        // ✅ Ensure we fetch the latest session (sorted by newest createdAt)
        const latestSession = await Session.findOne({ userId: decoded.userId }).sort({ createdAt: -1 });

        if (!latestSession) {
            console.log("❌ No active session found. User must log in again.");
            return res.status(401).json({ message: "⚠️ Session expired. Please log in again!" });
        }

        // ✅ Ensure the session matches the latest login
        if (latestSession.refreshToken !== token) {
            console.log("❌ Token mismatch detected. Invalidating all sessions.");
            await Session.deleteMany({ userId: decoded.userId }); // Force logout from all devices
            return res.status(401).json({ error: "⚠️ You have been logged out due to multiple logins!" });
        }

        // ✅ Enforce IP restriction
        if (latestSession.ipAddress !== req.ip) {
            console.log(`❌ IP Mismatch: Expected ${latestSession.ipAddress}, got ${req.ip}`);
            await Session.deleteOne({ _id: latestSession._id });
            res.clearCookie('refreshToken');
            return res.status(401).json({ error: "⚠️ Session compromised due to IP change" });
        }

        req.userId = decoded.userId;
        next();
    } catch (err) {
        console.log("❌ Token verification failed:", err.message);
        res.clearCookie('refreshToken');
        return res.status(403).json({ message: "⚠️ Forbidden: Invalid token" });
    }
};


module.exports = { authenticateJWT };
