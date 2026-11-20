import mongoose from 'mongoose';

const incidentSchema = new mongoose.Schema(
  {
    incidentId: {
      type: String,
      required: [true, 'incidentId is required'],
      unique: true,
      trim: true,
      index: true,
    },
    type: {
      type: String,
      required: [true, 'Incident type is required'],
      enum: [
        'MODIFIED_RECORD',
        'MISSING_SEQUENCE',
        'BROKEN_CHAIN',
        'REORDERED_RECORD',
        'INVALID_CHECKPOINT_SIGNATURE',
        'CHECKPOINT_CHAIN_MISMATCH',
        'CHECKPOINT_MISSING_LOG',
        'COLLECTOR_DISCONNECTED',
        'STORAGE_VERIFICATION_FAILED',
      ],
      index: true,
    },
    severity: {
      type: String,
      required: [true, 'Severity is required'],
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'medium',
      index: true,
    },
    sourceId: {
      type: String,
      required: [true, 'sourceId is required'],
      index: true,
    },
    description: {
      type: String,
      required: [true, 'Incident description is required'],
    },
    affectedEventIds: {
      type: [String],
      default: [],
    },
    evidenceReference: {
      type: String,
      default: null,
    },
    detectedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    status: {
      type: String,
      enum: ['OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'],
      default: 'OPEN',
      index: true,
    },
    resolutionNotes: {
      type: String,
      default: '',
    },
    resolvedBy: {
      type: String,
      default: null,
    },
    resolvedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

const Incident = mongoose.model('Incident', incidentSchema);

export default Incident;
