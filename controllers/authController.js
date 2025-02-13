const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');

const signupUser = async (req, res) => {
    try {
        const { name, email, password, type, adminId } = req.body;
        if (!name || !email || !password || !type) {
            return res.status(400).json({ error: "⚠️ All fields are required." });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "⚠️ Email already registered." });
        }

        const newUser = new User({
            name,
            email,
            password,
            userType: type,
            adminId: type === 'admin' ? adminId : null
        });

        await newUser.save();
        res.status(201).json({ message: "✅ User signed up successfully." });
    } catch (error) {
        console.error("❌ Signup Error:", error);
        res.status(500).json({ error: "⚠️ Internal Server Error" });
    }
};

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: "⚠️ Email or password is incorrect!" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "⚠️ Email or password is incorrect!" });
        }

        // Find the previous session (if any)
        const existingSession = await Session.findOne({ userId: user._id });

        if (existingSession) {
            console.warn(`⚠️ Existing session detected for user: ${user._id}, logging out previous session...`);

            // Delete the old session to invalidate the previous login
            await Session.deleteOne({ userId: user._id });
        }

        // Generate new JWT tokens
        const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        // Create and store new session
        const newSession = new Session({
            userId: user._id,
            ipAddress: req.ip,
            refreshToken,
            canceled: false,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        });

        await newSession.save();

        console.log(`✅ New session created for user: ${user._id} (IP: ${req.ip})`);

        // Set refresh token in HTTP-only cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            path: "/",
        });

        res.json({
            success: true,
            accessToken,
            redirectUrl: "/booking",
        });

    } catch (error) {
        console.error("❌ Login Error:", error);
        res.status(500).json({ error: "⚠️ Internal server error. Please try again later!" });
    }
};


const logout = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            return res.status(400).json({ error: "⚠️ No refresh token provided!" });
        }

        // Find session and delete it
        const deletedSession = await Session.deleteOne({ refreshToken });

        if (deletedSession.deletedCount === 0) {
            return res.status(404).json({ error: "⚠️ Session not found!" });
        }

        // Clear cookies
        res.clearCookie('refreshToken');

        res.json({ message: "✅ Logged out successfully" });
    } catch (error) {
        console.error("❌ Logout Error:", error);
        res.status(500).json({ error: "⚠️ Server error. Please try again." });
    }
};


const authenticateJWT = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "⚠️ Unauthorized: No token provided" });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const session = await Session.findOne({ userId: decoded.userId, refreshToken: token, active: true });
        if (!session) {
            return res.status(401).json({ message: "⚠️ Session expired. Please log in again!" });
        }
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: "⚠️ Forbidden: Invalid token" });
    }
};
module.exports = { signupUser, login, logout, authenticateJWT };
