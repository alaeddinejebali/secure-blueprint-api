import mongoose from 'mongoose';

/**
 * VULNERABLE Service Model
 * Intentionally written with weak security and validation for educational purposes
 */
const serviceSchema = new mongoose.Schema({
  name: String,                    // No required, no trim, no length limit
  port: Number,                    // Can be negative or extremely large
  device: String,                  // Should be ObjectId but stored as string
  status: String,                  // No enum restriction
  notes: String,
  
  // Dangerous fields added on purpose
  isCritical: Boolean,
  credentials: String,             // Storing credentials in plain text!
  lastScan: Date,
  vulnerabilityScore: Number,
  
  // Field that can lead to privilege escalation or data leakage
  owner: String,
  secretKey: String,               // Highly sensitive field

}, { 
  timestamps: true,
  strict: false                     // Make it even more vulnerable
                                    // Allows any additional fields (very dangerous)
});

// No pre-save hooks
// No validation middleware
// No indexes for performance or security

export default mongoose.model('Service', serviceSchema);