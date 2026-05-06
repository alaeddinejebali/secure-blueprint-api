import mongoose from 'mongoose';

/**
 * User Model — Secure version.
 *
 * KEY DIFFERENCES from the vulnerable version:
 *
 *  strict: true (default)
 *    The vulnerable model used strict: false, which told Mongoose to store any
 *    arbitrary field sent by the client — including fields like isAdmin or role
 *    injected via mass assignment. Strict mode (the default) silently ignores
 *    any field not declared in the schema.
 *
 *  required + unique on email
 *    Without required, a document can be created with no email at all.
 *    Without unique, two accounts can share the same email, breaking login logic
 *    and enabling account confusion attacks.
 *
 *  lowercase + trim on email
 *    Normalising the email before storage prevents duplicate accounts created
 *    by casing differences (User@Lab.com vs user@lab.com).
 *
 *  role enum
 *    The vulnerable version stored role as a free-form String — a client could
 *    register with role: 'superadmin' or any invented value. Restricting to a
 *    fixed enum means only known roles can ever be stored.
 *
 *  No dangerous fields
 *    Fields like apiKeys (array of secrets), lastLoginIp, resetToken, and
 *    failedLoginAttempts were included in the vulnerable model with no
 *    protection. They are omitted here; add them only when needed with
 *    proper access controls.
 *
 *  No plain-text password pre-save hook
 *    The vulnerable model had a pre-save hook that logged "Password saved in
 *    plain text!" and did nothing else. Password hashing is handled in the
 *    controller with bcrypt before the document is ever created.
 */
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      trim: true,
      minlength: [2, 'Username must be at least 2 characters'],
      maxlength: [50, 'Username must be at most 50 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,          // Enforced at the DB index level
      lowercase: true,       // Normalise before storage
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      // Passwords are hashed by the controller before reaching here.
      // minlength on the hash is not meaningful; length validation
      // is enforced by the Joi schema in the route layer instead.
    },
    role: {
      type: String,
      enum: ['user', 'admin'],  // Only these two values are accepted
      default: 'user',          // New accounts are always unprivileged by default
    },
  },
  {
    timestamps: true,
    // strict: true is the Mongoose default — listed here explicitly for clarity.
    // It ensures that fields not declared above (e.g. isAdmin, apiKeys) are
    // silently stripped and never written to the database.
    strict: true,
  }
);

export default mongoose.model('User', userSchema);
