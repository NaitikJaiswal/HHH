import jwt from 'jsonwebtoken';
import User from '../models/User.js';

/**
 * Generate a signed JWT token
 */
export const generateToken = (payload) => {
  const secret = process.env.JWT_SECRET || 'fallback_jwt_secret_for_development_only';
  const expiresIn = process.env.JWT_EXPIRES_IN || '24h';
  return jwt.sign(payload, secret, { expiresIn });
};

/**
 * Verify a JWT token
 */
export const verifyToken = (token) => {
  const secret = process.env.JWT_SECRET || 'fallback_jwt_secret_for_development_only';
  return jwt.verify(token, secret);
};

/**
 * Register a new user
 * Enforces strict role restriction: "admin" role cannot be selected via public registration
 */
export const registerUser = async (userData, requester = null) => {
  const { name, email, password, role } = userData;
  const normalizedEmail = email.toLowerCase().trim();

  // 1. Strict Administrator Role Security Gate
  if (role === 'admin') {
    // Only an existing authenticated administrator can create another administrator
    if (!requester || requester.role !== 'admin') {
      const err = new Error('Public registration for the administrator role is prohibited.');
      err.statusCode = 403;
      throw err;
    }
  }

  // Permitted self-registration roles: default to security_analyst
  const assignedRole = role || 'security_analyst';

  // 2. Check for duplicate account
  const existingUser = await User.findOne({ email: normalizedEmail });
  if (existingUser) {
    const err = new Error('A user with this email address already exists.');
    err.statusCode = 400;
    throw err;
  }

  // 3. Hash password using bcrypt
  const passwordHash = await User.hashPassword(password);

  // 4. Create user record
  const user = await User.create({
    name: name.trim(),
    email: normalizedEmail,
    passwordHash,
    role: assignedRole,
  });

  // 5. Generate authentication token
  const token = generateToken({
    id: user._id,
    email: user.email,
    role: user.role,
  });

  return {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    },
    token,
  };
};

/**
 * Authenticate user credentials and return JWT session
 */
export const loginUser = async ({ email, password }) => {
  const normalizedEmail = (email || '').toLowerCase().trim();

  // Find user by email
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) {
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  // Verify password hash
  const isMatch = await user.matchPassword(password);
  if (!isMatch) {
    const err = new Error('Invalid email or password.');
    err.statusCode = 401;
    throw err;
  }

  // Generate authentication token
  const token = generateToken({
    id: user._id,
    email: user.email,
    role: user.role,
  });

  return {
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    },
    token,
  };
};

/**
 * Retrieve user by ID without exposing password hash
 */
export const getUserById = async (id) => {
  const user = await User.findById(id).select('-passwordHash');
  if (!user) {
    const err = new Error('User not found.');
    err.statusCode = 404;
    throw err;
  }
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
};

export default {
  generateToken,
  verifyToken,
  registerUser,
  loginUser,
  getUserById,
};
