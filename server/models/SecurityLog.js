import mongoose from 'mongoose';

const securityLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  },
  eventType: {
    type: String,
    required: true,
  },
  eventDescription: {
    type: String,
    required: true,
  },
  severity: {
    type: String,
    enum: ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    required: true,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  ipAddress: {
    type: String,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Index for faster queries
securityLogSchema.index({ userId: 1, createdAt: -1 });
securityLogSchema.index({ severity: 1, createdAt: -1 });

export default mongoose.model('SecurityLog', securityLogSchema);

