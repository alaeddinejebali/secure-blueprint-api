import mongoose from 'mongoose';

/**
 * VULNERABLE User Model
 * Intentionally insecure - Full of security anti-patterns for educational purposes
 */
const userSchema = new mongoose.Schema({
  username: String,                 // No required, no unique, no trim
  email: String,                    // No unique constraint, no lowercase
  password: String,                 // Stored in PLAIN TEXT!
  role: String,                     // No enum → can be set to anything
  isAdmin: Boolean,                 // Can be manipulated
  
  // Dangerous fields (intentionally added)
  resetToken: String,
  apiKeys: Array,                   // Storing sensitive keys
  lastLoginIp: String,
  failedLoginAttempts: Number,
  isLocked: Boolean,

}, { 
  timestamps: true,
  strict: false                     // Make it even more vulnerable
                                    // Allows any additional fields (very dangerous)
});

// NO password hashing middleware (Critical vulnerability)
userSchema.pre('save', function(next) {
  console.log('⚠️  Password saved in plain text!');
  next();
});

// Very weak password comparison
userSchema.methods.comparePassword = function(candidatePassword) {
  return this.password === candidatePassword;   // Plain text comparison
};

export default mongoose.model('User', userSchema);