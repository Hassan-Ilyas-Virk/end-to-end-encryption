import mongoose from 'mongoose';

const messageSchema = new mongoose.Schema({
  senderId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  encryptedContent: {
    type: String,
    required: true,
  },
  iv: {
    type: String,
    required: true,
  },
  authTag: {
    type: String,
    required: true,
  },
  nonce: {
    type: String,
    required: true,
    unique: true,
  },
  timestamp: {
    type: Number,
    required: true,
  },
  sequenceNumber: {
    type: Number,
    required: true,
  },
  signature: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for faster queries
messageSchema.index({ senderId: 1, receiverId: 1, timestamp: 1 });
messageSchema.index({ nonce: 1 }, { unique: true });

export default mongoose.model('Message', messageSchema);

