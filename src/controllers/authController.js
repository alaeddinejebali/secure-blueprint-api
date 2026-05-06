import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

/**
 * Generates a signed JWT for a given user.
 *
 * SECURITY: Tokens are signed with a strong secret from the environment (never hardcoded)
 * and expire after 7 days. The vulnerable version used a weak hardcoded secret
 * ('superweaksecret123') and set no expiry — a forged or stolen token would be
 * valid forever.
 */
const generateToken = (user) =>
  jwt.sign(
    { id: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

/**
 * POST /api/auth/register
 *
 * SECURITY IMPROVEMENTS over the vulnerable version:
 *  - Input is validated by Joi before this function is called (see routes/auth.js).
 *  - Password is hashed with bcrypt (cost factor 12) before storage.
 *    Plain-text storage means a single DB breach exposes every user's password.
 *  - Only the token is returned — never the created user document, which would
 *    include the hashed password and any other internal fields.
 *  - Duplicate email errors are caught and returned as a 409, not a 500,
 *    without leaking Mongoose internals.
 */
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // SECURITY: Hash the password before storing it.
    // Cost factor 12 means ~300ms per hash — fast enough for UX, slow enough
    // to make brute-forcing a leaked hash infeasible.
    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({ username, email, password: hashedPassword });

    const token = generateToken(user);

    res.status(201).json({ message: 'User created', token });
  } catch (error) {
    // SECURITY: Mongoose duplicate key error code is 11000.
    // Return a clear 409 without exposing any raw error details.
    if (error.code === 11000) {
      return res.status(409).json({ message: 'Email already in use' });
    }
    // All other errors are passed to the global error handler in server.js
    // which returns a generic 500 — no internal details reach the client.
    throw error;
  }
};

/**
 * POST /api/auth/login
 *
 * SECURITY IMPROVEMENTS over the vulnerable version:
 *  - Input is validated by Joi before this function is called (see routes/auth.js).
 *  - Password is compared with bcrypt.compare() — never with === on plain text.
 *  - Both "user not found" and "wrong password" return the exact same 401 message.
 *    Different messages for each case let attackers enumerate valid email addresses.
 *  - Returns 200 (not 201) — 201 means "resource created", which is semantically wrong.
 */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    // SECURITY: Use a single generic message for both "no user" and "wrong password".
    // Separate messages (e.g. "User not found" vs "Incorrect password") allow
    // attackers to enumerate which emails are registered.
    const isMatch = user && await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateToken(user);

    res.status(200).json({ message: 'Login successful', token });
  } catch (error) {
    throw error;
  }
};
