const express = require('express');
const router = express.Router();

// Route to render searchFlights.hbs
router.get('/searchFlights', (req, res) => {
    res.render('searchFlights'); // Ensure 'searchFlights.hbs' exists in the correct folder
});

module.exports = router;
