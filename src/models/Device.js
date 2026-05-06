import mongoose from 'mongoose';

/**
 * Device Model — Secure version.
 *
 * KEY DIFFERENCES from the vulnerable version:
 *
 *  strict: true (default)
 *    Prevents clients from storing arbitrary extra fields (mass assignment).
 *    The vulnerable model accepted any field the client sent, including
 *    injected fields like isAdmin or apiKey.
 *
 *  required fields
 *    name and ip are required so incomplete records cannot be created,
 *    preventing null-reference errors in downstream logic.
 *
 *  status enum
 *    Restricts status to known values. A free-form string could be used to
 *    store XSS payloads (e.g. <script>alert(1)</script>) that fire when a
 *    frontend renders the value without escaping.
 *
 *  Removed dangerous fields
 *    The vulnerable model included isAdmin, userId, and apiKey with no
 *    protection. Privilege flags (isAdmin) have no place in a device record.
 *    Sensitive values (apiKey) should never be stored unencrypted in a
 *    general-purpose collection. Owner linkage is handled via the owner field
 *    (ObjectId reference to User) set server-side, never from req.body.
 *
 *  owner set server-side
 *    The owner field is populated in the controller from req.user (the verified
 *    JWT payload) — the client never supplies it. In the vulnerable version,
 *    userId was a free-form string supplied by the client and never verified,
 *    allowing ownership spoofing.
 */
const deviceSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Device name is required'],
      trim: true,
      maxlength: [100, 'Name must be at most 100 characters'],
    },
    ip: {
      type: String,
      required: [true, 'IP address is required'],
      trim: true,
      match: [
        /^(\d{1,3}\.){3}\d{1,3}$/,
        'Please provide a valid IPv4 address',
      ],
    },
    type: {
      type: String,
      trim: true,
      maxlength: [50, 'Type must be at most 50 characters'],
    },
    status: {
      type: String,
      enum: ['online', 'offline', 'unknown'],
      default: 'unknown',
    },
    notes: {
      type: String,
      maxlength: [500, 'Notes must be at most 500 characters'],
    },
    // SECURITY: Owner is a reference to the User who created this device.
    // It is set in the controller from req.user.id (the verified JWT payload)
    // and is never accepted from req.body.
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
  },
  {
    timestamps: true,
    strict: true,
  }
);

export default mongoose.model('Device', deviceSchema);
