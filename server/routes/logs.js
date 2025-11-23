import express from 'express';
import SecurityLog from '../models/SecurityLog.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Get user's security logs
router.get('/', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    
    const logs = await SecurityLog.find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .limit(limit);
    
    res.json(logs);
  } catch (error) {
    console.error('Get logs error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create security log
router.post('/', authenticate, async (req, res) => {
  try {
    const { eventType, eventDescription, severity, metadata } = req.body;
    
    const log = new SecurityLog({
      userId: req.userId,
      eventType,
      eventDescription,
      severity,
      metadata,
    });
    
    await log.save();
    res.status(201).json(log);
  } catch (error) {
    console.error('Create log error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

