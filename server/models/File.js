import mongoose from 'mongoose';

const fileSchema = new mongoose.Schema({
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
  filename: {
    type: String,
    required: true,
  },
  encryptedData: {
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
  },
  timestamp: {
    type: Number,
    required: true,
  },
  fileSize: {
    type: Number,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for faster queries
fileSchema.index({ senderId: 1, receiverId: 1, createdAt: -1 });

export default mongoose.model('File', fileSchema);

