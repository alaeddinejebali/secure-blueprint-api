import mongoose from 'mongoose';

/**
 * Service Model — Secure version.
 *
 * KEY DIFFERENCES from the vulnerable version:
 *
 *  strict: true (default)
 *    The vulnerable model used strict: false — any field from the client
 *    was stored as-is. A client could inject arbitrary fields and have them
 *    persisted to the database.
 *
 *  port validation
 *    The vulnerable model stored port as a plain Number with no constraints.
 *    A client could supply -1, 0, or 99999 — values that are not valid ports.
 *    min/max enforce the real TCP port range (1–65535).
 *
 *  device as ObjectId reference
 *    The vulnerable model stored device as a plain String — no referential
 *    integrity, easy to spoof. An ObjectId ref ties a service to a real
 *    document in the Device collection.
 *
 *  status enum
 *    Restricts values to prevent stored XSS via unescaped status strings.
 *
 *  Removed dangerous fields
 *    credentials and secretKey had no business being in a Mongoose model.
 *    Storing credentials in plain text in a database is a critical vulnerability.
 *    vulnerabilityScore is domain-specific and should live in a dedicated
 *    findings/scan model, not mixed into service records.
 *
 *  owner set server-side
 *    Same pattern as Device — populated from req.user.id in the controller,
 *    never from req.body.
 */
const serviceSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Service name is required'],
      trim: true,
      maxlength: [100, 'Name must be at most 100 characters'],
    },
    port: {
      type: Number,
      required: [true, 'Port is required'],
      min: [1, 'Port must be between 1 and 65535'],
      max: [65535, 'Port must be between 1 and 65535'],
    },
    device: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Device',
      required: [true, 'Device reference is required'],
    },
    status: {
      type: String,
      enum: ['active', 'inactive', 'unknown'],
      default: 'unknown',
    },
    isCritical: {
      type: Boolean,
      default: false,
    },
    notes: {
      type: String,
      maxlength: [500, 'Notes must be at most 500 characters'],
    },
    lastScan: {
      type: Date,
    },
    // SECURITY: Owner is set from req.user.id in the controller.
    // Never accepted from the client.
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

export default mongoose.model('Service', serviceSchema);
