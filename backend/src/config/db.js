import mongoose from 'mongoose';

/**
 * Connect to MongoDB Atlas / Local MongoDB instance
 */
export const connectDB = async (uri = process.env.MONGODB_URI) => {
  if (!uri) {
    throw new Error('MONGODB_URI environment variable is not defined.');
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
