import Source from '../models/Source.js';
import { verifyToken } from '../services/authService.js';

/**
 * Authenticates log submissions from Python collectors and authorized services.
 * Accepts:
 *  - X-API-Key: <key>
 *  - Authorization: Bearer <key_or_jwt>
 */
export const authenticateCollector = async (req, res, next) => {
  const globalKey = process.env.COLLECTOR_API_KEY || 'default_collector_secret_key';

  let providedKey = req.headers['x-api-key'];

  if (!providedKey && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      providedKey = parts[1];
    }
  }

  if (!providedKey) {
    return res.status(401).json({
      success: false,
      message: 'Collector authentication failed: API key or bearer token required.',
    });
  }

  // 1. Direct match with global collector API key
  if (providedKey === globalKey) {
    req.collector = { id: 'global_collector', type: 'global' };
    return next();
  }

  // 2. Check if it's a valid JWT from a dashboard user (admin or security_analyst)
  try {
    const decoded = verifyToken(providedKey);
    if (decoded && ['admin', 'security_analyst'].includes(decoded.role)) {
      req.user = decoded;
      req.collector = { id: decoded.id, type: 'user', role: decoded.role };
      return next();
    }
  } catch {
    // Not a valid user JWT, proceed to source check
  }

  // 3. Match against source-specific API keys in the database
  try {
    const source = await Source.findOne({ apiKey: providedKey });
    if (source) {
      req.collector = { id: source.sourceId, type: 'source' };
      return next();
    }
  } catch (err) {
    // DB query error
  }

  return res.status(401).json({
    success: false,
    message: 'Collector authentication failed: Invalid API key.',
  });
};

export default authenticateCollector;
