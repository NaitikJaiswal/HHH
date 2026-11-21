import mongoose from 'mongoose';

const auditEventSchema = new mongoose.Schema(
  {
    actorId: {
      type: String,
      required: [true, 'actorId is required'],
      index: true,
    },
    action: {
      type: String,
      required: [true, 'action is required'],
      index: true,
    },
    resource: {
      type: String,
      required: [true, 'resource is required'],
      index: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
    result: {
      type: String,
      enum: ['SUCCESS', 'FAILURE', 'DENIED'],
      default: 'SUCCESS',
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: false,
  }
);

const AuditEvent = mongoose.model('AuditEvent', auditEventSchema);

export default AuditEvent;
