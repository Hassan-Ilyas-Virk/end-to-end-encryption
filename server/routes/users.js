import express from 'express';
import User from '../models/User.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Get all users (for contact list)
router.get('/', authenticate, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.userId } })
      .select('username publicKeyECDH publicKeySign createdAt')
      .sort({ username: 1 });

    res.json(users);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user public keys
router.get('/:userId/keys', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .select('publicKeyECDH publicKeySign');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      publicKeyECDH: user.publicKeyECDH,
      publicKeySign: user.publicKeySign,
    });
  } catch (error) {
    console.error('Get user keys error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Update user public keys
router.put('/:userId/keys', authenticate, async (req, res) => {
  try {
    // Ensure user can only update their own keys
    console.log(`Update keys request for userId: ${req.params.userId}, authenticated user: ${req.userId}`);
    console.log(`Type of req.params.userId: ${typeof req.params.userId}`);
    console.log(`Type of req.userId: ${typeof req.userId}`);
    console.log(`req.userId.toString(): ${req.userId.toString()}`);
    console.log(`Comparison result: ${req.params.userId} !== ${req.userId.toString()} = ${req.params.userId !== req.userId.toString()}`);

    // Convert ObjectId to string for comparison
    if (req.params.userId !== req.userId.toString()) {
      console.log('❌ Unauthorized key update attempt');
      return res.status(403).json({ error: 'Unauthorized to update these keys' });
    }

    console.log('✅ Authorization check passed');

    const { publicKeyECDH, publicKeySign } = req.body;

    if (!publicKeyECDH || !publicKeySign) {
      return res.status(400).json({ error: 'Both ECDH and ECDSA public keys are required' });
    }

    const user = await User.findByIdAndUpdate(
      req.userId,
      {
        publicKeyECDH,
        publicKeySign,
        updatedAt: Date.now()
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`✓ Updated public keys for user: ${user.username}`);

    res.json({
      message: 'Keys updated successfully',
      publicKeyECDH: user.publicKeyECDH,
      publicKeySign: user.publicKeySign
    });
  } catch (error) {
    console.error('Update user keys error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

