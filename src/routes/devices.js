import express from 'express';
import Joi from 'joi';
import Device from '../models/Device.js';
import protect from '../middleware/auth.js';
import validate from '../middleware/validate.js';

const router = express.Router();

/**
 * Joi schema for creating / updating a device.
 *
 * SECURITY: Whitelisting specific fields here (combined with stripUnknown in
 * the validate middleware) prevents mass assignment. A client cannot inject
 * fields like isAdmin, owner, or role — they are stripped before the data
 * reaches the controller.
 */
const deviceSchema = Joi.object({
  name: Joi.string().min(1).max(100).required(),
  ip: Joi.string()
    .ip({ version: ['ipv4'], cidr: 'forbidden' })
    .required(),
  type: Joi.string().max(50),
  status: Joi.string().valid('online', 'offline', 'unknown'),
  notes: Joi.string().max(500).allow(''),
});

const updateDeviceSchema = deviceSchema.fork(
  ['name', 'ip'],
  (field) => field.optional()
);

// SECURITY: All routes below require a valid JWT.
// The protect middleware verifies the token and populates req.user.
// In the vulnerable version there was no authentication at all —
// anyone who could reach the server could read or modify all devices.
router.use(protect);

// GET all devices — returns only devices owned by the requesting user.
// SECURITY: Scoping queries to req.user.id prevents IDOR (Insecure Direct
// Object Reference) — a user cannot retrieve another user's devices.
router.get('/', async (req, res) => {
  try {
    const devices = await Device.find({ owner: req.user.id });
    res.json(devices);
  } catch {
    throw new Error('Failed to fetch devices');
  }
});

// GET a single device by ID.
// SECURITY: The owner filter ensures a user cannot fetch a device that
// belongs to someone else by guessing its ObjectId.
router.get('/:id', async (req, res) => {
  try {
    const device = await Device.findOne({ _id: req.params.id, owner: req.user.id });
    if (!device) {
      // Return 404 regardless of whether the record doesn't exist or belongs
      // to another user — no information about other users' data is revealed.
      return res.status(404).json({ message: 'Device not found' });
    }
    res.json(device);
  } catch {
    throw new Error('Failed to fetch device');
  }
});

// POST — create a new device.
// SECURITY: validate() strips unknown fields and enforces types/lengths.
// owner is set from req.user.id — never from req.body.
router.post('/', validate(deviceSchema), async (req, res) => {
  try {
    const device = await Device.create({ ...req.body, owner: req.user.id });
    res.status(201).json(device);
  } catch {
    throw new Error('Failed to create device');
  }
});

// PUT — update a device.
// SECURITY: owner filter prevents a user from updating another user's device.
router.put('/:id', validate(updateDeviceSchema), async (req, res) => {
  try {
    const device = await Device.findOneAndUpdate(
      { _id: req.params.id, owner: req.user.id },
      req.body,
      { new: true, runValidators: true }  // runValidators re-runs schema validation on update
    );
    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }
    res.json(device);
  } catch {
    throw new Error('Failed to update device');
  }
});

// DELETE — remove a device.
// SECURITY: owner filter prevents a user from deleting another user's device.
router.delete('/:id', async (req, res) => {
  try {
    const device = await Device.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
    if (!device) {
      return res.status(404).json({ message: 'Device not found' });
    }
    res.json({ message: 'Device deleted' });
  } catch {
    throw new Error('Failed to delete device');
  }
});

export default router;
