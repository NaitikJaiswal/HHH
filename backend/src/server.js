import dotenv from 'dotenv';
dotenv.config();

import app from './app.js';
import { connectDB, disconnectDB } from './config/db.js';

const PORT = process.env.PORT || 5000;

let server;

const startServer = async () => {
  try {
    // Attempt database connection if URI is configured
    if (process.env.MONGODB_URI) {
      await connectDB();
    } else {
      console.warn('[Warning] MONGODB_URI not provided. Starting server without active DB connection.');
    }

    server = app.listen(PORT, () => {
      console.log(`[Server] HHH SecureLog Backend running on port ${PORT} [${process.env.NODE_ENV || 'development'}]`);
      console.log(`[Server] Health check available at: http://localhost:${PORT}/health`);
    });
  } catch (error) {
    console.error(`[Server Error] Failed to initialize server: ${error.message}`);
    process.exit(1);
  }
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
