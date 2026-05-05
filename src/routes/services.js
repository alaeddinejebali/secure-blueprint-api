import express from 'express';
import Service from '../models/Service.js';

const router = express.Router();

/**
 * VULNERABLE Services Routes
 * No authentication, no validation, no authorization
 */

// GET all services - No protection
router.get('/', async (req, res) => {
  try {
    // Vulnerable: No authentication + allows query injection
    const services = await Service.find(req.query); 
    res.json(services);
  } catch (error) {
    res.status(500).json({ error: error.message }); // Exposes error details
  }
});

// CREATE service - No validation
router.post('/', async (req, res) => {
  try {
    // Vulnerable: Mass Assignment possible due to strict: false in model
    const service = await Service.create(req.body);
    res.status(201).json(service);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET single service by ID - Vulnerable to IDOR
router.get('/:id', async (req, res) => {
  try {
    const service = await Service.findById(req.params.id);
    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.json(service);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// UPDATE service - No validation or auth
router.put('/:id', async (req, res) => {
  try {
    const service = await Service.findByIdAndUpdate(
      req.params.id, 
      req.body, 
      { new: true }
    );
    if (!service) {
      return res.status(404).json({ message: 'Service not found' });
    }
    res.json(service);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE service - No protection
router.delete('/:id', async (req, res) => {
  try {
    await Service.findByIdAndDelete(req.params.id);
    res.json({ message: 'Service deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;