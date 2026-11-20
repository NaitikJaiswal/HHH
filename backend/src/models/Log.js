import mongoose from 'mongoose';

const logSchema = new mongoose.Schema(
  {
    eventId: {
      type: String,
      required: [true, 'eventId is required'],
      unique: true,
      trim: true,
      index: true,
    },
    sourceId: {
      type: String,
      required: [true, 'sourceId is required'],
      trim: true,
      index: true,
    },
    eventType: {
      type: String,
      required: [true, 'eventType is required'],
      trim: true,
      index: true,
    },
    message: {
      type: String,
      required: [true, 'Log message is required'],
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    timestamp: {
      type: Date,
      required: [true, 'Client timestamp is required'],
      index: true,
    },
    serverTimestamp: {
      type: Date,
      default: Date.now,
      immutable: true,
      index: true,
    },
    sequenceNumber: {
      type: Number,
      required: [true, 'sequenceNumber is required'],
      index: true,
    },
    previousHash: {
      type: String,
      required: [true, 'previousHash is required'],
    },
    currentHash: {
      type: String,
      required: [true, 'currentHash is required'],
      index: true,
    },
    storageReference: {
      type: String,
      default: null,
      index: true,
    },
    verificationStatus: {
      type: String,
      enum: ['VERIFIED', 'TAMPERED', 'PENDING'],
      default: 'PENDING',
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// Compound index to guarantee sequence uniqueness per log source
logSchema.index({ sourceId: 1, sequenceNumber: 1 }, { unique: true });

const Log = mongoose.model('Log', logSchema);

export default Log;
