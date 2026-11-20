import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import morgan from 'morgan';
import { isDBConnected } from './config/db.js';
import { notFound, errorHandler } from './middleware/errorMiddleware.js';

const app = express();

// 1. Security Headers with Helmet
app.use(helmet());

// 2. CORS Configuration
const allowedOrigin = process.env.CLIENT_URL || 'http://localhost:5173';
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. mobile apps, curl, Python collector)
      if (!origin || origin === allowedOrigin || origin === 'http://localhost:5173') {
        callback(null, true);
      } else {
        callback(null, true); // Permissive in development, can restrict in production
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Collector-Key', 'Idempotency-Key'],
  })
);

// 3. Request Logging (disabled during automated test runs)
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('dev'));
}

// 4. Request Body Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 5. Health Check & Service Info Endpoints
const healthCheckHandler = (req, res) => {
  res.status(200).json({
    success: true,
    message: 'HHH SecureLog Backend API is operational',
    data: {
      status: 'UP',
      service: 'HHH-SecureLog-Backend',
      timestamp: new Date().toISOString(),
      database: isDBConnected() ? 'CONNECTED' : 'DISCONNECTED',
      environment: process.env.NODE_ENV || 'development',
    },
  });
};

app.get('/health', healthCheckHandler);
app.get('/api/health', healthCheckHandler);

app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'HHH (Hash. Hunt. Harden.) – SecureLog Backend Platform',
    version: '1.0.0',
    documentation: '/api/docs',
  });
});

// 6. 404 & Centralized Error Middleware (Exported so routes can be mounted before them)
export const mountErrorHandlers = (application) => {
  application.use(notFound);
  application.use(errorHandler);
};

// Mount error handlers by default
mountErrorHandlers(app);

export default app;
