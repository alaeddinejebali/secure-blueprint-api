import express from 'express';
import Joi from 'joi';
import Service from '../models/Service.js';
import protect from '../middleware/auth.js';
import validate from '../middleware/validate.js';

const router = express.Router();

/**
 * Joi schema for creating a service.
 *
 * SECURITY: Whitelisting fields prevents mass assignment.
 * Fields like owner, credentials, and secretKey are not in the schema —
 * they are stripped by the validate middleware before reaching the controller.
 */
const serviceSchema = Joi.object({
  name: Joi.string().min(1).max(100).required(),
  port: Joi.number().integer().min(1).max(65535).required(),
  device: Joi.string().hex().length(24).required(), // Must be a valid ObjectId string
  status: Joi.string().valid('active', 'inactive', 'unknown'),
  isCritical: Joi.boolean(),
  notes: Joi.string().max(500).allow(''),
  lastScan: Joi.date().iso(),
});

const updateServiceSchema = serviceSchema.fork(
  ['name', 'port', 'device'],
  (field) => field.optional()
);

// SECURITY: All routes require a valid JWT.
// The vulnerable version had no authentication — every service record
// was openly readable and writable by anyone.
router.use(protect);

// GET all services.
// SECURITY: In the vulnerable version, req.query was passed directly into
// Service.find() — allowing MongoDB operators like $gt, $ne, $where to be
// injected via URL parameters (NoSQL Injection).
// Here we only accept a known, safe query parameter (device filter) and
// always scope results to the authenticated user's owner ID.
router.get('/', async (req, res) => {
  try {
    const filter = { owner: req.user.id };

    // Optional filter by device — validated as a hex ObjectId before use.
    if (req.query.device) {
      if (!/^[a-fA-F0-9]{24}$/.test(req.query.device)) {
        return res.status(400).json({ message: 'Invalid device id' });
      }
      filter.device = req.query.device;
    }

    const services = await Service.find(filter);
    res.json(services);
  } catch {
    throw new Error('Failed to fetch services');
  }
});

// GET a single service by ID.
// SECURITY: owner filter prevents IDOR — a user cannot access another
// user's service record by guessing its ObjectId.
router.get('/:id', async (req, res) => {
  try {
    const service = await Service.findOne({ _id: req.params.id, owner: req.user.id });
    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.json(service);
  } catch {
    throw new Error('Failed to fetch service');
  }
});

// POST — create a new service.
// SECURITY: validate() enforces the schema and strips unknown fields.
// owner is set from req.user.id — the client cannot supply or spoof it.
router.post('/', validate(serviceSchema), async (req, res) => {
  try {
    const service = await Service.create({ ...req.body, owner: req.user.id });
    res.status(201).json(service);
  } catch {
    throw new Error('Failed to create service');
  }
});

// PUT — update a service.
// SECURITY: owner filter ensures a user can only update their own records.
// runValidators re-runs Mongoose schema validation on the updated fields.
router.put('/:id', validate(updateServiceSchema), async (req, res) => {
  try {
    const service = await Service.findOneAndUpdate(
      { _id: req.params.id, owner: req.user.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.json(service);
  } catch {
    throw new Error('Failed to update service');
  }
});

// DELETE — remove a service.
// SECURITY: owner filter prevents a user from deleting another user's service.
router.delete('/:id', async (req, res) => {
  try {
    const service = await Service.findOneAndDelete({ _id: req.params.id, owner: req.user.id });
    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.json({ message: 'Service deleted' });
  } catch {
    throw new Error('Failed to delete service');
  }
});

export default router;
