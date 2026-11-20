/**
 * Generic Validation Middleware Factory
 * Wraps validator functions and intercepts requests with invalid payloads.
 */
export const validate = (validatorFn) => {
  return (req, res, next) => {
    const { isValid, errors } = validatorFn(req.body);

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: errors[0] || 'Invalid request payload',
        errors,
      });
    }

    next();
  };
};

export default validate;
