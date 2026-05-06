/**
 * Joi validation middleware factory.
 *
 * SECURITY: The vulnerable version passed req.body directly into Mongoose
 * with no validation whatsoever. This allowed:
 *  - Arbitrary field injection (mass assignment)
 *  - Oversized payloads stored in the database
 *  - Malformed types causing downstream errors that leaked internal details
 *
 * This middleware validates incoming request bodies against a Joi schema
 * before the request reaches any controller or database call.
 * If validation fails, a 400 is returned with the specific field error —
 * safe to expose since it contains no internal system details.
 *
 * Usage:
 *   router.post('/', validate(mySchema), controllerFn);
 */
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body, {
    abortEarly: false,   // Return all field errors at once, not just the first
    stripUnknown: true,  // SECURITY: Silently drop any fields not in the schema
                         // This prevents mass assignment — extra fields like
                         // isAdmin, role, apiKey are stripped before they reach
                         // the controller or database.
  });

  if (error) {
    const messages = error.details.map((d) => d.message);
    return res.status(400).json({ message: 'Validation failed', errors: messages });
  }

  next();
};

export default validate;
