const express = require('express');
const app = express();
const path = require('path');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const checkSessionRoutes = require('./routes/checkSessionRoutes');
require('dotenv').config();


const mongoose = require('./mongo');

app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use((req, res, next) => {
    console.log(`[${req.method}] ${req.url}`);
    next();
});


let refreshTokenRoutes, flightRoutes, logoutRoutes, authRoutes, bookingRoutes;
try {
    refreshTokenRoutes = require('./routes/refreshTokenRoutes');
    flightRoutes = require('./routes/flightRoutes');
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
app.get('/login', (req, res) => res.render('login'));
app.get('/searchFlights', (req, res) => res.render('searchFlights'));
app.get('/booking', (req, res) => res.render('booking')); // Add this for the booking page

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/refresh-token', refreshTokenRoutes);
app.use('/api/logout', logoutRoutes);
app.use('/api/booking', bookingRoutes); // Add booking API route
app.use('/api/auth', checkSessionRoutes); // ✅ Now available at /api/auth/check-session
app.use('/', flightRoutes);

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server is running on port ${PORT}`);
});
