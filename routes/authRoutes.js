const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const authController = require('../controllers/authController');
const authenticateJWT = authController.authenticateJWT;
const User = require('../models/User'); // Import User model
const crypto = require("crypto");
const bcrypt = require("bcrypt");  // ✅ Import bcrypt
const nodemailer = require("nodemailer");  // ✅ Import nodemailer
 

// Validation middleware for signup
const validateSignup = [
    body('name')
        .trim()
        .isLength({ min: 3 })
        .escape()
        .withMessage('Name must be at least 3 characters long.'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email format.'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long.'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];


// Verification route
router.get("/verify/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.render("verify", { message: "⚠️ Invalid or expired verification token." });
        }

        // Mark user as verified
        user.isVerified = true;
        user.verificationToken = null; // Clear token after verification
        await user.save();

        res.render("verify", { message: "✅ Email verified successfully! You can now log in." });
    } catch (error) {
        console.error("❌ Verification Error:", error);
        res.render("verify", { message: "⚠️ Server error. Please try again later." });
    }
});



router.post("/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists" });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate verification token
        const verificationToken = crypto.randomUUID();

        // Create new user with verification token
        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            isVerified: false, // ✅ Ensure this field is stored
            verificationToken
        });

        await newUser.save();

        // Send verification email
        await sendVerificationEmail(email, verificationToken);

        res.status(201).json({ message: "User registered! Check your email for verification." });
    } catch (error) {
        console.error("❌ Registration Error:", error);
        res.status(500).json({ message: "Server error" });
    }
});


// Render signup form
router.get('/signup', (req, res) => res.render('signup'));

// Render login form
router.get('/login', (req, res) => res.render('login'));

// Render for verification
router.get('/verify', (req, res) => {
    res.render('verify', { message: "Please check your email for verification!" });
});


console.log("Auth Controller Contents:", authController);

// API routes
router.post('/signup', validateSignup, authController.signupUser);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

// Use authenticateJWT middleware for protected routes
router.use('/protected', authenticateJWT);

// Protected route (example)
router.get('/protected-route', authenticateJWT, (req, res) => {
    res.send('This is a protected route!');
});

module.exports = router;
