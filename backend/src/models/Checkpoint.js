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
    schema_version: {
      type: String,
      default: 'logn-checkpoint-fss-v1',
      index: true,
    },
    sourceId: {
      type: String,
      required: [true, 'sourceId is required'],
      trim: true,
      index: true,
    },
    start_sequence: {
      type: Number,
      default: 1,
      index: true,
    },
    end_sequence: {
      type: Number,
      default: 0,
      index: true,
    },
    lastSequenceNumber: {
      type: Number,
      required: [true, 'lastSequenceNumber is required'],
      index: true,
    },
    event_count: {
      type: Number,
      default: 0,
    },
    chainHeadHash: {
      type: String,
      required: [true, 'chainHeadHash is required'],
    },
    merkle_root: {
      type: String,
      default: null,
      index: true,
    },
    merkle_leaf_hashes: {
      type: [String],
      default: [],
    },
    merkle_tree_algorithm: {
      type: String,
      default: 'HHH-CONTRACT-DUP-v1',
    },
    fss_epoch: {
      type: Number,
      default: null,
      index: true,
    },
    mpk: {
      type: String,
      default: null,
      index: true,
    },
    epoch_public_key: {
      type: String,
      default: null,
    },
    fss_auth_path: {
      type: mongoose.Schema.Types.Mixed,
      default: [],
    },
    fss_signature: {
      type: String,
      default: null,
    },
    fss_bundle: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    timestamp: {
      type: Date,
      required: [true, 'Checkpoint timestamp is required'],
    },
    signature: {
      type: String,
      required: [true, 'Checkpoint signature is required'],
    },
    publicKey: {
      type: String,
      default: null,
    },
    signing_key_id: {
      type: String,
      default: null,
    },
    signature_algorithm: {
      type: String,
      default: 'Ed25519-MKT-FSS',
    },
    signature_input: {
      type: String,
      default: 'logn-checkpoint-fss-v1',
    },
    blockchain: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
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

checkpointSchema.virtual('checkpoint_id').get(function () {
  return this.checkpointId;
});

checkpointSchema.virtual('source_id').get(function () {
  return this.sourceId;
});

const Checkpoint = mongoose.model('Checkpoint', checkpointSchema);

export default Checkpoint;
