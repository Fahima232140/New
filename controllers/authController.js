require('dotenv').config();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');
const zxcvbn = require('zxcvbn');
const nodemailer = require('nodemailer'); // For sending emails
 

const signupUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ error: "⚠️ All fields are required." });
        }

        // ✅ Validate password strength
        const passwordStrength = zxcvbn(password);
        if (passwordStrength.score < 3) {
            return res.status(400).json({ error: "⚠️ Password too weak. Use a stronger password!" });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "⚠️ Email already registered." });
        }

        // ✅ Create user with verification token
        const verificationToken = uuidv4();  // Unique token for email verification
        const newUser = new User({
            name,
            email,
            password, // Will be hashed in the model
            isVerified: false,  // New users are NOT verified initially
            verificationToken
        });
        
        await newUser.save();

        // ✅ Send verification email
        await sendVerificationEmail(email, verificationToken);

        res.status(201).json({ message: "✅ User signed up successfully. Please verify your email." });

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
            console.log("❌ User not found!");
            return res.status(401).json({ error: "⚠️ Email or password is incorrect!" });
        }

        console.log("🔍 Checking email:", email);
        console.log("✅ User found:", user);
        console.log("🔍 Entered password:", password);
        console.log("🔍 Stored hashed password:", user.password);

        // ✅ Check if email is verified
        if (!user.isVerified) {
            console.log("❌ Email not verified!");
            return res.status(403).json({ error: "⚠️ Please verify your email before logging in." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        console.log("🔍 Password match:", isMatch);

        if (!isMatch) {
            console.log("❌ Incorrect password");
            return res.status(401).json({ error: "⚠️ Email or password is incorrect!" });
        }

        console.log("✅ Password is correct! Checking session...");

        // Find previous session using `ipAddress`
        const existingSession = await Session.findOne({ userId: user._id });

        if (existingSession) {
            console.warn(`⚠️ Existing session detected for user: ${user._id}, logging out previous session...`);

            // Delete the old session to invalidate the previous login
            await Session.deleteOne({ userId: user._id });
        }

        // ✅ Generate new JWT tokens
        const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        // ✅ Create and store new session (without deviceId)
        const newSession = new Session({
            userId: user._id,
            ipAddress: req.ip,  // ✅ Only use ipAddress
            refreshToken,
            canceled: false,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
        });

        await newSession.save();

        console.log(`✅ New session created for user: ${user._id} (IP: ${req.ip})`);

        // ✅ Set refresh token in HTTP-only cookie
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "Strict",
            path: "/",
        });

        res.json({
            success: true,
            accessToken,
            redirectUrl: "/booking", // ✅ Redirect user to booking page
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

        // Delete the session based on the user ID instead of the refreshToken
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

const refreshAccessToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;
        if (!refreshToken) {
            return res.status(400).json({ error: "⚠️ No refresh token provided!" });
        }

        const session = await Session.findOne({ refreshToken });
        if (!session) {
            return res.status(404).json({ error: "⚠️ Session not found!" });
        }

        const newAccessToken = jwt.sign({ userId: session.userId }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ success: true, accessToken: newAccessToken });
    } catch (error) {
        console.error("❌ Refresh Token Error:", error);
        res.status(500).json({ error: "⚠️ Server error. Please try again." });
    }
};


console.log("📧 Email User:", process.env.EMAIL_USER);
console.log("🔑 Email Pass:", process.env.EMAIL_PASS ? "Loaded" : "Not Loaded")

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER, // Your Gmail address
        pass: process.env.EMAIL_PASS  // Your App Password
    }
});

const sendVerificationEmail = async (userEmail, token) => {
    const verificationLink = `${process.env.BACKEND_URL}/api/auth/verify/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: userEmail,
        subject: "Verify Your Email",
        html: `<p>Click here to verify your email: <a href="${verificationLink}">${verificationLink}</a></p>`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("✅ Verification email sent successfully!");
    } catch (error) {
        console.error("❌ Email sending failed:", error);
    }
};



module.exports = { 
    signupUser, 
    login,  // ✅ Ensure login is included here
    logout, 
    authenticateJWT, 
    refreshAccessToken,
    sendVerificationEmail
};
