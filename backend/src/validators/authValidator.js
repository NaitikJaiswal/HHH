/**
 * Validates registration payload
 */
export const validateRegister = (data) => {
  const errors = [];
  const { name, email, password, role } = data || {};

  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    errors.push('Name is required and must be at least 2 characters long.');
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!email || typeof email !== 'string' || !emailRegex.test(email.trim())) {
    errors.push('A valid email address is required.');
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    errors.push('Password must be at least 8 characters long.');
  } else {
    // Check complexity: at least 1 uppercase, 1 lowercase, 1 number
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter.');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter.');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number.');
    }
  }

  if (role && !['admin', 'security_analyst', 'auditor'].includes(role)) {
    errors.push('Invalid role. Permitted roles are: admin, security_analyst, auditor.');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

/**
 * Validates login payload
 */
export const validateLogin = (data) => {
  const errors = [];
  const { email, password } = data || {};

  if (!email || typeof email !== 'string' || email.trim().length === 0) {
    errors.push('Email is required.');
  }

  if (!password || typeof password !== 'string' || password.length === 0) {
    errors.push('Password is required.');
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

export default {
  validateRegister,
  validateLogin,
};
