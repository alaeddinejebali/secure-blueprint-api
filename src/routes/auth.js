import express from 'express';
import Joi from 'joi';
import { register, login } from '../controllers/authController.js';
import validate from '../middleware/validate.js';

const router = express.Router();

/**
 * Joi schema for registration.
 *
 * SECURITY: The vulnerable version passed req.body directly to User.create()
 * with zero validation. This schema enforces:
 *  - All required fields are present
 *  - Email is a valid format and is normalised to lowercase
 *  - Password is at least 8 characters, preventing trivially weak passwords
 *  - No extra fields (stripUnknown in the validate middleware drops them)
 */
const registerSchema = Joi.object({
  username: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().lowercase().required(),
  password: Joi.string().min(8).max(128).required(),
});

/**
 * Joi schema for login.
 */
const loginSchema = Joi.object({
  email: Joi.string().email().lowercase().required(),
  password: Joi.string().required(),
});

// validate() runs before the controller — invalid requests never reach the DB.
router.post('/register', validate(registerSchema), register);
router.post('/login', validate(loginSchema), login);

export default router;
