import express from 'express';
import Message from '../models/Message.js';
import SecurityLog from '../models/SecurityLog.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Get messages between two users
router.get('/:otherUserId', authenticate, async (req, res) => {
  try {
    const { otherUserId } = req.params;
    const userId = req.userId;
    
    const messages = await Message.find({
      $or: [
        { senderId: userId, receiverId: otherUserId },
        { senderId: otherUserId, receiverId: userId },
      ],
    }).sort({ timestamp: 1 }).limit(100);
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Send message
router.post('/', authenticate, async (req, res) => {
  try {
    const {
      receiverId,
      encryptedContent,
      iv,
      authTag,
      nonce,
      timestamp,
      sequenceNumber,
      signature,
    } = req.body;
    
    const message = new Message({
      senderId: req.userId,
      receiverId,
      encryptedContent,
      iv,
      authTag,
      nonce,
      timestamp,
      sequenceNumber,
      signature,
    });
    
    await message.save();
    
    await SecurityLog.create({
      userId: req.userId,
      eventType: 'MESSAGE_ENCRYPT_SUCCESS',
      eventDescription: 'Message encrypted and sent',
      severity: 'INFO',
      metadata: { messageId: message._id },
    });
    
    res.status(201).json(message);
  } catch (error) {
    console.error('Send message error:', error);
    
    if (error.code === 11000) {
      await SecurityLog.create({
        userId: req.userId,
        eventType: 'REPLAY_ATTACK_DETECTED',
        eventDescription: 'Duplicate nonce detected',
        severity: 'CRITICAL',
      });
      return res.status(400).json({ error: 'Duplicate nonce - possible replay attack' });
    }
    
    res.status(500).json({ error: error.message });
  }
});

// Delete all messages (for testing/debugging)
router.delete('/all', authenticate, async (req, res) => {
  try {
    const result = await Message.deleteMany({
      $or: [
        { senderId: req.userId },
        { receiverId: req.userId },
      ],
    });
    
    console.log(`Deleted ${result.deletedCount} messages for user ${req.userId}`);
    res.json({ deletedCount: result.deletedCount });
  } catch (error) {
    console.error('Delete all messages error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

