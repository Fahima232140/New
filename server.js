require("dotenv").config();  // ✅ Load environment variables at the top!
const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const checkSessionRoutes = require('./routes/checkSessionRoutes');
const bodyParser = require("body-parser");
const paymentRoutes = require("./routes/paymentRoutes");


const mongoose = require('./mongo');


// ✅ Ensure Stripe API key is loaded AFTER dotenv
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
console.log("🔑 STRIPE_SECRET_KEY:", process.env.STRIPE_SECRET_KEY);


app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());

app.use((req, res, next) => {
    console.log(`[${req.method}] ${req.url}`);
    next();
});


let refreshTokenRoutes, logoutRoutes, authRoutes, bookingRoutes;
try {
    refreshTokenRoutes = require('./routes/refreshTokenRoutes');
    logoutRoutes = require('./routes/logoutRoutes');
    authRoutes = require('./routes/authRoutes');
    bookingRoutes = require('./routes/bookingRoutes'); // Add the booking route
} catch (err) {
    console.error("❌ Route import failed:", err);
    process.exit(1);
}

// Set up Handlebars
app.set('views', path.join(__dirname, 'templates'));
app.set('view engine', 'hbs');

// Routes for rendering pages
app.get('/signup', (req, res) => res.render('signup'));
app.get('/home', (req, res) => res.render('home'));
app.get('/login', (req, res) => res.render('login'));
app.get('/booking', (req, res) => res.render('booking')); // Add this for the booking page
app.get('/payment', (req, res) => {
    res.render('payment'); // This will render "payment.hbs" inside "templates"
});
app.get('/about', (req, res) => {
    res.render('about'); // ✅ Correct way to render about.hbs
});

app.get('/contact', (req, res) => {
    res.render('contact'); // ✅ Correct way to render about.hbs
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/refresh-token', refreshTokenRoutes);
app.use('/api/logout', logoutRoutes);
app.use('/api/booking', bookingRoutes); // Add booking API route
app.use('/api/auth', checkSessionRoutes); // ✅ Now available at /api/auth/check-session
app.use("/api/payment", paymentRoutes); 
app.use(express.static(path.join(__dirname, 'public')));

console.log("📧 Email User:", process.env.EMAIL_USER);
console.log("🔑 Email Pass:", process.env.EMAIL_PASS ? "Loaded" : "Not Loaded");

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});
