const mongoose = require('../mongo');
const bcrypt = require('bcrypt');


const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    userType: { type: String, enum: ['user', 'admin'], required: true },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null }
});

// Hash password before saving
UserSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});


// Method to compare input password with hashed password
UserSchema.methods.comparePassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};


module.exports = mongoose.model('User', UserSchema);




