import authService from '../services/authService.js';

/**
 * Handle User Registration
 * POST /api/auth/register
 */
export const register = async (req, res, next) => {
  try {
    const result = await authService.registerUser(req.body, req.user);
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: result,
    });
  } catch (error) {
    res.status(error.statusCode || 500);
    next(error);
  }
};

/**
 * Handle User Login
 * POST /api/auth/login
 */
export const login = async (req, res, next) => {
  try {
    const result = await authService.loginUser(req.body);
    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: result,
    });
  } catch (error) {
    res.status(error.statusCode || 401);
    next(error);
  }
};

/**
 * Get Current Authenticated User Profile
 * GET /api/auth/me
 */
export const getMe = async (req, res, next) => {
  try {
    // If database is connected, fetch full fresh record, otherwise use token payload
    let user;
    try {
      user = await authService.getUserById(req.user.id);
    } catch {
      user = req.user;
    }

    res.status(200).json({
      success: true,
      message: 'Current user profile retrieved',
      data: user,
    });
  } catch (error) {
    next(error);
  }
};

export default {
  register,
  login,
  getMe,
};
