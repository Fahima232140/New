const Booking = require('../models/Booking');

// Create a new booking
exports.createBooking = async (req, res) => {
    try {
        const { name, email, passport, departure, destination, date } = req.body;

        if (!name || !email || !passport || !departure || !destination || !date) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const newBooking = new Booking({ name, email, passport, departure, destination, date });
        await newBooking.save();

        res.status(201).json({ message: 'Booking successful', booking: newBooking });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

// Get all bookings
exports.getAllBookings = async (req, res) => {
    try {
        const bookings = await Booking.find();
        res.status(200).json(bookings);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
