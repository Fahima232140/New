const express = require('express');
const router = express.Router();
const bookingController = require('../controllers/bookingController');
const { authenticateJWT } = require("../middleware/authMiddleware");


router.post('/create', bookingController.createBooking);
router.get('/all', bookingController.getAllBookings);

// ✅ Add protected booking route with authentication
router.post('/book', authenticateJWT, async (req, res) => {
    // Booking logic here...
    res.json({ message: "Booking route accessed successfully!" });
});

module.exports = router;
