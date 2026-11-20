import dotenv from 'dotenv';
dotenv.config();

import app from './app.js';
import { connectDB, disconnectDB, isValidMongoUri } from './config/db.js';

const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === 'production';

let server;

const startServer = async () => {
  const uri = process.env.MONGODB_URI;

  if (uri && isValidMongoUri(uri)) {
    try {
      await connectDB(uri);
    } catch (dbError) {
      console.warn(`\n[Database Warning] Could not establish MongoDB connection: ${dbError.message}`);
      if (isProduction) {
        console.error('[Fatal] Exiting process because database connection is required in production.');
        process.exit(1);
      }
      console.warn('[Database Notice] Running in development mode with offline/mock database resilience.\n');
    }
  } else {
    console.warn('\n================================================================');
    console.warn('⚠️  MONGODB_URI in backend/.env is unconfigured or a placeholder.');
    console.warn(`   Current value: "${uri || 'undefined'}"`);
    console.warn('   To connect to MongoDB Atlas, set MONGODB_URI to:');
    console.warn('   mongodb+srv://<username>:<password>@<cluster>.mongodb.net/securelog');
    console.warn('   Or for a local MongoDB instance:');
    console.warn('   mongodb://127.0.0.1:27017/securelog');
    console.warn('================================================================\n');

    if (isProduction) {
      console.error('[Fatal] Valid MONGODB_URI is required in production.');
      process.exit(1);
    }
  }

  server = app.listen(PORT, () => {
    console.log(`[Server] HHH SecureLog Backend running on http://localhost:${PORT} [${process.env.NODE_ENV || 'development'}]`);
    console.log(`[Server] Health check available at: http://localhost:${PORT}/health`);
  });
};

// Graceful Shutdown Handler
const gracefulShutdown = async (signal) => {
  console.log(`\n[Server] Received ${signal}. Starting graceful shutdown...`);

  if (server) {
    server.close(async () => {
      console.log('[Server] HTTP server closed.');
      try {
        await disconnectDB();
        console.log('[Server] Graceful shutdown completed.');
        process.exit(0);
      } catch (err) {
        console.error(`[Server Error] Error during DB disconnect: ${err.message}`);
        process.exit(1);
      }
    });
  } else {
    process.exit(0);
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Unhandled Rejection] Reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('[Uncaught Exception] Error:', error);
  process.exit(1);
});

startServer();
