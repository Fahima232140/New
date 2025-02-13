const mongoose = require('mongoose');

const uri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/Backend";

mongoose.connect(uri)
  .then(() => {
    console.log('Connected to MongoDB Successfully...');
  })
  .catch(err => {
    console.error('Could not connect to MongoDB...', err);
  });

module.exports = mongoose;
