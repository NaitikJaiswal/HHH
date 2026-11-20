import mongoose from 'mongoose';

const sourceSchema = new mongoose.Schema(
  {
    sourceId: {
      type: String,
      required: [true, 'sourceId is required'],
      unique: true,
      trim: true,
      index: true,
    },
    name: {
      type: String,
      required: [true, 'Source name is required'],
      trim: true,
    },
    sourceType: {
      type: String,
      enum: ['linux', 'windows', 'application', 'network', 'cloud'],
      default: 'application',
    },
    status: {
      type: String,
      enum: ['ACTIVE', 'INACTIVE', 'DEGRADED', 'DISCONNECTED'],
      default: 'ACTIVE',
      index: true,
    },
    apiKey: {
      type: String,
      select: false, // Hidden by default from queries
    },
    lastSequenceNumber: {
      type: Number,
      default: 0,
    },
    lastHash: {
      type: String,
      default: '0000000000000000000000000000000000000000000000000000000000000000', // Genesis Hash (64 zeros)
    },
    lastHeartbeat: {
      type: Date,
      default: null,
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
  }
);

const Source = mongoose.model('Source', sourceSchema);

export default Source;
