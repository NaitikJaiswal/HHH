/**
 * Deterministic JSON Canonicalization (RFC 8785 compliant subset)
 * Ensures that any two objects with equivalent data serialize to identical strings,
 * regardless of key ordering or runtime representation differences.
 */
export const canonicalize = (obj) => {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  // Handle Dates deterministically in ISO string format
  if (obj instanceof Date) {
    return JSON.stringify(obj.toISOString());
  }

  // Handle Arrays recursively
  if (Array.isArray(obj)) {
    const serializedElements = obj.map((element) => {
      const canonical = canonicalize(element);
      return canonical === undefined ? 'null' : canonical;
    });
    return `[${serializedElements.join(',')}]`;
  }

  // Handle Objects: sort keys lexicographically by UTF-16 code units
  const sortedKeys = Object.keys(obj).sort();
  const serializedEntries = [];

  for (const key of sortedKeys) {
    const value = obj[key];
    if (value !== undefined && typeof value !== 'function' && typeof value !== 'symbol') {
      serializedEntries.push(`${JSON.stringify(key)}:${canonicalize(value)}`);
    }
  }

  return `{${serializedEntries.join(',')}}`;
};

export default canonicalize;
