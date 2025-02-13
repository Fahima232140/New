const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();
const authController = require('../controllers/authController'); 

const authenticateJWT = authController.authenticateJWT;  


// Validation middleware for signup
const validateSignup = [
    body('name').trim().isLength({ min: 3 }).escape().withMessage('Name must be at least 3 characters long.'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email format.'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    }
];


// Render signup form
router.get('/signup', (req, res) => res.render('signup'));

// Render login form
router.get('/login', (req, res) => res.render('login'));

console.log("Auth Controller Contents:", authController);


// Define routes
router.post('/signup', authController.signupUser);
router.post('/login', authController.login);
router.post('/logout', authController.logout);


// ✅ Fix: Ensure authenticateJWT is used correctly
router.get('/protected-route', authenticateJWT, (req, res) => {
    res.send('This is a protected route!');
});

module.exports = router;
