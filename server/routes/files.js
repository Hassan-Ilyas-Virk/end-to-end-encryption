import express from 'express';
import File from '../models/File.js';
import SecurityLog from '../models/SecurityLog.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Get shared files
router.get('/:otherUserId', authenticate, async (req, res) => {
  try {
    const { otherUserId } = req.params;
    const userId = req.userId;
    
    const files = await File.find({
      $or: [
        { senderId: userId, receiverId: otherUserId },
        { senderId: otherUserId, receiverId: userId },
      ],
    }).sort({ createdAt: -1 }).select('-encryptedData');
    
    res.json(files);
  } catch (error) {
    console.error('Get files error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get single file (with encrypted data)
router.get('/download/:fileId', authenticate, async (req, res) => {
  try {
    const { fileId } = req.params;
    const userId = req.userId;
    
    const file = await File.findOne({
      _id: fileId,
      $or: [{ senderId: userId }, { receiverId: userId }],
    });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    await SecurityLog.create({
      userId: req.userId,
      eventType: 'FILE_DECRYPT_SUCCESS',
      eventDescription: `File download: ${file.filename}`,
      severity: 'INFO',
      metadata: { fileId: file._id, fileSize: file.fileSize },
    });
    
    res.json(file);
  } catch (error) {
    console.error('Download file error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Upload file
router.post('/', authenticate, async (req, res) => {
  try {
    const {
      receiverId,
      filename,
      encryptedData,
      iv,
      authTag,
      nonce,
      timestamp,
      fileSize,
    } = req.body;
    
    const file = new File({
      senderId: req.userId,
      receiverId,
      filename,
      encryptedData,
      iv,
      authTag,
      nonce,
      timestamp,
      fileSize,
    });
    
    await file.save();
    
    await SecurityLog.create({
      userId: req.userId,
      eventType: 'FILE_ENCRYPT_SUCCESS',
      eventDescription: `File uploaded: ${filename}`,
      severity: 'INFO',
      metadata: { fileId: file._id, fileSize },
    });
    
    res.status(201).json(file);
  } catch (error) {
    console.error('Upload file error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;

