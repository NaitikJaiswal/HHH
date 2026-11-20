import mongoose from 'mongoose';
import dns from 'dns';

// Ensure reliable SRV DNS resolution for MongoDB Atlas on Windows environments
try {
  dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4']);
} catch {
  // Gracefully fallback to system default if setting DNS is restricted
}

/**
 * Checks whether a MongoDB connection string has a valid protocol and is not a placeholder
 */
export const isValidMongoUri = (uri) => {
  if (!uri || typeof uri !== 'string') return false;
  const trimmed = uri.trim();
  if (trimmed.includes('YOUR_MONGODB_') || trimmed.includes('replace_with') || trimmed.includes('<password>')) {
    return false;
  }
  return trimmed.startsWith('mongodb://') || trimmed.startsWith('mongodb+srv://');
};

/**
 * Connect to MongoDB Atlas / Local MongoDB instance
 */
export const connectDB = async (uri = process.env.MONGODB_URI) => {
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is not defined.');
  }

  if (!isValidMongoUri(uri)) {
    throw new Error(
      `Invalid MongoDB URI format: "${uri}". Expected connection string starting with "mongodb://" or "mongodb+srv://".`
    );
  }

  // Mask credentials in logs for security
  const maskedUri = uri.replace(/\/\/[^:]+:[^@]+@/, '//***:***@');

  try {
    const conn = await mongoose.connect(uri, {
      autoIndex: true,
      serverSelectionTimeoutMS: 5000,
    });

    console.log(`[Database] MongoDB Connected: ${conn.connection.host} (${conn.connection.name})`);
    return conn;
  } catch (error) {
    console.error(`[Database Error] Connection failed to ${maskedUri}: ${error.message}`);
    throw error;
  }
};

/**
 * Disconnect from MongoDB (for graceful shutdown and isolated test teardown)
 */
export const disconnectDB = async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    console.log('[Database] MongoDB connection closed.');
  }
};

/**
 * Returns the current database connection health
 */
export const isDBConnected = () => {
  return mongoose.connection.readyState === 1;
};

export default connectDB;
