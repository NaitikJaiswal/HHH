import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import app from '../app.js';
import { connectDB, isDBConnected } from '../config/db.js';

describe('Server & Express Setup Verification', () => {
  it('GET /health should return 200 with standardized health status', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toContain('operational');
    expect(res.body.data).toHaveProperty('status', 'UP');
    expect(res.body.data).toHaveProperty('service', 'HHH-SecureLog-Backend');
    expect(res.body.data).toHaveProperty('timestamp');
  });

  it('GET /api/health should also return 200 with standardized health status', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.status).toBe('UP');
  });

  it('GET / should return 200 with platform info', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.message).toContain('HHH');
  });

  it('Unknown routes should return 404 in standardized format', async () => {
    const res = await request(app).get('/api/non-existent-route-999');
    expect(res.status).toBe(404);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toContain('Resource Not Found');
  });

  it('connectDB should throw an error when URI is missing', async () => {
    await expect(connectDB('')).rejects.toThrow('MONGODB_URI environment variable is not defined.');
  });
});
