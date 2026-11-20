import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import app from '../app.js';
import User from '../models/User.js';
import { generateToken } from '../services/authService.js';
import { protect } from '../middleware/authMiddleware.js';
import { authorizeRoles } from '../middleware/roleMiddleware.js';

describe('Milestone 3: Authentication & Role-Based Access Control', () => {
  // In-memory user fixture store for testing without depending on external DB
  const mockUsers = new Map();

  beforeEach(() => {
    mockUsers.clear();
    vi.restoreAllMocks();

    // Mock User.findOne
    vi.spyOn(User, 'findOne').mockImplementation(({ email }) => {
      const user = mockUsers.get(email.toLowerCase());
      if (!user) return Promise.resolve(null);
      return Promise.resolve({
        ...user,
        matchPassword: async (pwd) => bcrypt.compare(pwd, user.passwordHash),
      });
    });

    // Mock User.create
    vi.spyOn(User, 'create').mockImplementation((data) => {
      const newUser = {
        _id: 'user_' + Math.random().toString(36).substring(2, 9),
        name: data.name,
        email: data.email.toLowerCase(),
        passwordHash: data.passwordHash,
        role: data.role || 'security_analyst',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      mockUsers.set(newUser.email, newUser);
      return Promise.resolve(newUser);
    });

    // Mock User.findById
    vi.spyOn(User, 'findById').mockImplementation((id) => {
      for (const u of mockUsers.values()) {
        if (u._id === id) {
          return {
            select: vi.fn().mockResolvedValue(u),
          };
        }
      }
      return {
        select: vi.fn().mockResolvedValue(null),
      };
    });
  });

  describe('User Registration (POST /api/auth/register)', () => {
    it('1. Successfully registers a security analyst with valid data', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Jane Analyst',
          email: 'jane@securelog.io',
          password: 'Password123!',
          role: 'security_analyst',
        });

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe('jane@securelog.io');
      expect(res.body.data.user.role).toBe('security_analyst');
      expect(res.body.data).toHaveProperty('token');
      expect(res.body.data.user).not.toHaveProperty('passwordHash');
    });

    it('2. Prevents privilege escalation: rejects public registration for admin role', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Malicious Actor',
          email: 'attacker@evil.com',
          password: 'Password123!',
          role: 'admin',
        });

      expect(res.status).toBe(403);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Public registration for the administrator role is prohibited');
    });

    it('3. Rejects registration if email already exists (duplicate prevention)', async () => {
      // First registration
      await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Existing User',
          email: 'duplicate@securelog.io',
          password: 'Password123!',
        });

      // Second registration with same email
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Another User',
          email: 'duplicate@securelog.io',
          password: 'Password123!',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('already exists');
    });

    it('4. Rejects invalid registration payloads (short password, invalid email)', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'A',
          email: 'not-an-email',
          password: '123',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors.length).toBeGreaterThan(0);
    });
  });

  describe('User Login (POST /api/auth/login)', () => {
    beforeEach(async () => {
      // Seed a test user
      const passwordHash = await bcrypt.hash('SecurePass123!', 10);
      mockUsers.set('auditor@securelog.io', {
        _id: 'user_auditor_1',
        name: 'Auditor One',
        email: 'auditor@securelog.io',
        passwordHash,
        role: 'auditor',
        createdAt: new Date().toISOString(),
      });
    });

    it('5. Successfully logs in with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'auditor@securelog.io',
          password: 'SecurePass123!',
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.user.email).toBe('auditor@securelog.io');
      expect(res.body.data).toHaveProperty('token');
    });

    it('6. Rejects login with incorrect password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'auditor@securelog.io',
          password: 'WrongPassword999!',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid email or password');
    });

    it('7. Rejects login with unregistered email', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'unknown@securelog.io',
          password: 'SecurePass123!',
        });

      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('Invalid email or password');
    });
  });

  describe('Protected Routes & RBAC (/api/auth/me & Role Guards)', () => {
    it('8. Accessing /api/auth/me without token is rejected (401)', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toContain('No authentication token provided');
    });

    it('9. Accessing /api/auth/me with valid token returns user profile', async () => {
      const token = generateToken({
        id: 'test_user_id',
        email: 'analyst@securelog.io',
        role: 'security_analyst',
      });

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.data.email).toBe('analyst@securelog.io');
      expect(res.body.data.role).toBe('security_analyst');
    });

    it('10. RBAC role guard blocks unauthorized role and allows authorized role', async () => {
      // Create a test sub-app with admin-only endpoint
      const testApp = express();
      testApp.use(express.json());
      testApp.get('/admin-only', protect, authorizeRoles('admin'), (req, res) => {
        res.status(200).json({ success: true, message: 'Welcome Admin' });
      });

      // Token for security_analyst
      const analystToken = generateToken({
        id: 'user_analyst',
        email: 'analyst@securelog.io',
        role: 'security_analyst',
      });

      // Token for admin
      const adminToken = generateToken({
        id: 'user_admin',
        email: 'admin@securelog.io',
        role: 'admin',
      });

      // Analyst attempting admin route -> 403 Forbidden
      const analystRes = await request(testApp)
        .get('/admin-only')
        .set('Authorization', `Bearer ${analystToken}`);
      expect(analystRes.status).toBe(403);
      expect(analystRes.body.success).toBe(false);
      expect(analystRes.body.message).toContain('not authorized');

      // Admin accessing admin route -> 200 OK
      const adminRes = await request(testApp)
        .get('/admin-only')
        .set('Authorization', `Bearer ${adminToken}`);
      expect(adminRes.status).toBe(200);
      expect(adminRes.body.success).toBe(true);
    });
  });
});
