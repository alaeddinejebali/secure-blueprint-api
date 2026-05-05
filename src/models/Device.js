import mongoose from 'mongoose';

/**
 * VULNERABLE Device Model
 * This version has minimal validation and is intentionally insecure
 */
const deviceSchema = new mongoose.Schema({
  name: String,                     // No required, no trim
  ip: String,                       // No IP validation - can store anything
  type: String,                     // No enum restriction
  status: String,                   // Can be set to anything
  lastSeen: Date,
  notes: String,
  
  // Dangerous fields that should not be freely allowed
  userId: String,                   // Can be manipulated
  isAdmin: Boolean,                 // Privilege escalation possible
  apiKey: String,                   // Sensitive data might be stored
  
}, { 
  timestamps: true,
  strict: false                     // Make it even more vulnerable
                                    // Allows any additional fields (very dangerous)
});

// No additional security middleware or pre-save hooks
// No indexes, no validation, no sanitization

export default mongoose.model('Device', deviceSchema);