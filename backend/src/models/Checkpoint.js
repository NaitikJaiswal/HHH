import mongoose from 'mongoose';

const checkpointSchema = new mongoose.Schema(
  {
    checkpointId: {
      type: String,
      required: [true, 'checkpointId is required'],
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
    lastSequenceNumber: {
      type: Number,
      required: [true, 'lastSequenceNumber is required'],
      index: true,
    },
    chainHeadHash: {
      type: String,
      required: [true, 'chainHeadHash is required'],
    },
    timestamp: {
      type: Date,
      required: [true, 'Checkpoint timestamp is required'],
    },
    signature: {
      type: String,
      required: [true, 'Ed25519 signature is required'],
    },
    publicKey: {
      type: String,
      required: [true, 'Ed25519 public key is required'],
    },
    storageReference: {
      type: String,
      default: null,
    },
    status: {
      type: String,
      enum: ['VALID', 'INVALID'],
      default: 'VALID',
    },
  },
  {
    timestamps: true,
  }
);

const Checkpoint = mongoose.model('Checkpoint', checkpointSchema);

export default Checkpoint;
