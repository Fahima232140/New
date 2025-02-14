const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, default: null }
});

// ✅ Hash password before saving user
userSchema.pre('save', async function (next) {  // ⬅️ FIXED (was UserSchema.pre)
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// ✅ Compare password method
userSchema.methods.comparePassword = async function (candidatePassword) {  // ⬅️ FIXED (was UserSchema.methods)
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema); // ⬅️ FIXED (was UserSchema)
module.exports = User;
