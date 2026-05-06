import jwt from 'jsonwebtoken';

/**
 * Authentication middleware — protects routes from unauthenticated access.
 *
 * SECURITY: In the vulnerable version, ALL device and service routes were
 * completely open — anyone who could reach the API could read, create, update,
 * or delete any record without any credentials.
 *
 * This middleware:
 *  1. Requires a valid Bearer token in the Authorization header.
 *  2. Verifies the token signature against the strong JWT_SECRET env variable.
 *  3. Attaches the decoded user payload to req.user for downstream use.
 *  4. Returns a generic 401 for both missing and invalid tokens — intentionally
 *     avoiding different messages that could reveal whether a token exists.
 */
const protect = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    // SECURITY: Do not reveal why verification failed (expired, malformed, wrong signature).
    // A specific message like "Token expired" helps attackers understand the system.
    return res.status(401).json({ message: 'Unauthorized' });
  }
};

export default protect;
