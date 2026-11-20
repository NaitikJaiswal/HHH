import { S3Client } from '@aws-sdk/client-s3';

/**
 * AWS S3 Configuration for WORM (Write Once, Read Many) Immutable Storage.
 *
 * SECURITY REQUIREMENT:
 * The target S3 bucket MUST have Bucket Versioning and S3 Object Lock enabled
 * at the time of bucket creation. Object Lock cannot be retroactively enabled on an
 * existing standard bucket.
 *
 * Retention Mode: COMPLIANCE
 * In COMPLIANCE mode, no user (including the AWS root account) can overwrite, delete,
 * or shorten the retention period of an object until the retention period expires.
 */

const region = process.env.AWS_REGION || 'us-east-1';
const bucketName = process.env.AWS_S3_BUCKET || 'securelog-immutable-evidence';
const retentionDays = parseInt(process.env.AWS_S3_RETENTION_DAYS, 10) || 30;
const storageMode = (process.env.STORAGE_MODE || 'mock').toLowerCase();

let s3ClientInstance = null;

export const isS3Configured = () => {
  return (
    storageMode === 's3' &&
    Boolean(process.env.AWS_ACCESS_KEY_ID) &&
    Boolean(process.env.AWS_SECRET_ACCESS_KEY)
  );
};

export const getS3Client = () => {
  if (s3ClientInstance) {
    return s3ClientInstance;
  }

  if (!isS3Configured()) {
    return null;
  }

  s3ClientInstance = new S3Client({
    region,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
  });

  return s3ClientInstance;
};

export const getStorageConfig = () => ({
  mode: storageMode,
  isS3Active: isS3Configured(),
  region,
  bucketName,
  retentionDays,
  objectLockMode: 'COMPLIANCE',
});

export default {
  isS3Configured,
  getS3Client,
  getStorageConfig,
};
