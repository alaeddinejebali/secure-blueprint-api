import express from 'express';
import Device from '../models/Device.js';

const router = express.Router();

// No authentication middleware

router.get('/', async (req, res) => {
  try {
    const devices = await Device.find();
    res.json(devices);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post('/', async (req, res) => {
  try {
    const device = await Device.create(req.body);  // No validation
    res.status(201).json(device);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

export default router;