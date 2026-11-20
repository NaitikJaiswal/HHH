/**
 * @module canonicalJson
 * @description Deterministic JSON serialization following the LOGN-HASH-v1 specification
 * defined in docs/technical-integration-contract.md §1.3.2 and §1.3.4.
 *
 * Rules enforced:
 *   - Object keys sorted by Unicode code point (ascending, same as JS default sort for BMP chars)
 *   - No whitespace, no trailing commas
 *   - Unicode characters in string values: preserved as UTF-8 (NOT escaped to \uXXXX)
 *   - Booleans: lowercase true / false (JSON native)
 *   - Null values: "null" (JSON native)
 *   - Numbers: JSON native integer or float — no scientific notation for integers
 *   - Arrays: element order preserved; undefined elements become null
 *   - Nested objects: keys sorted recursively
 *   - Maximum nesting depth: 10 levels (beyond → string "[DEEP_OBJECT]")
 *   - If metadata is null or absent at top level: serialize as {}
 *   - Circular references: throw TypeError
 *   - undefined at top level: throw TypeError
 *   - Non-finite numbers (Infinity, NaN, -Infinity): throw RangeError
 *
 * IMPORTANT: This module uses a custom serializer to preserve non-ASCII characters.
 * JSON.stringify escapes non-ASCII in some environments; this implementation does not.
 */

'use strict';

const MAX_DEPTH = 10;
const DEEP_OBJECT_SENTINEL = '[DEEP_OBJECT]';

/**
 * Recursively sort all object keys by Unicode code point (ascending).
 * Arrays have their element order preserved. Values at depth > MAX_DEPTH are
 * replaced with the string "[DEEP_OBJECT]" per §1.3.4 of the integration contract.
 *
 * @param {unknown} value - The value to process.
 * @param {number} [depth=0] - Current recursion depth (0-based).
 * @returns {unknown} A new value with all nested object keys sorted.
 */
export function sortKeysDeep(value, depth = 0) {
  if (depth > MAX_DEPTH) {
    return DEEP_OBJECT_SENTINEL;
  }

  if (value === null || value === undefined) {
    // null/undefined metadata → {} is handled by the caller (hashLogEvent / canonicalJson for metadata)
    return value;
  }

  if (Array.isArray(value)) {
    // Arrays: preserve element order, recurse into each element
    return value.map((el) => sortKeysDeep(el, depth + 1));
  }

  if (typeof value === 'object') {
    // Sort keys by Unicode code point (JS String comparison via Array.prototype.sort
    // uses UTF-16 code units, which is equivalent to Unicode code point order for all
    // Basic Multilingual Plane characters — covers all expected field names)
    const sortedKeys = Object.keys(value).sort();
    const result = {};
    for (const key of sortedKeys) {
      const v = value[key];
      if (v === undefined) {
        // undefined values in objects: omit per JSON semantics
        continue;
      }
      result[key] = sortKeysDeep(v, depth + 1);
    }
    return result;
  }

  // Primitive: string, number, boolean — return as-is
  return value;
}

/**
 * Serialize a value to a canonical JSON string that:
 *   - Sorts all object keys by Unicode code point (recursively)
 *   - Produces no whitespace
 *   - Preserves non-ASCII characters as-is (UTF-8, NOT \uXXXX escaping)
 *   - Rejects circular references (throws TypeError)
 *   - Rejects non-finite numbers (throws RangeError)
 *   - Rejects undefined at the top level (throws TypeError)
 *
 * This custom serializer avoids JSON.stringify's optional non-ASCII escaping
 * behaviour, which would violate §1.3.2 of the LOGN-HASH-v1 specification.
 *
 * @param {unknown} value - The value to serialize.
 * @param {Set<object>} [_seen] - Internal cycle-detection set (do not pass externally).
 * @returns {string} Canonical JSON string with no whitespace.
 * @throws {TypeError} If value is undefined, contains circular references, or is a function/symbol.
 * @throws {RangeError} If a non-finite number (Infinity, NaN, -Infinity) is encountered.
 */
export function canonicalJson(value, _seen = new Set()) {
  // Reject undefined at top level
  if (value === undefined) {
    throw new TypeError('canonicalJson: undefined is not a valid JSON value');
  }

  // null
  if (value === null) {
    return 'null';
  }

  // boolean
  if (typeof value === 'boolean') {
    return value ? 'true' : 'false';
  }

  // number
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new RangeError(
        `canonicalJson: non-finite number is not allowed in JSON: ${value}`
      );
    }
    // RFC 8785 §3.2.2.3: -0 must be serialized as 0
    if (Object.is(value, -0)) {
      return '0';
    }
    // Use JSON.stringify for number serialization — it handles integer vs. float
    // correctly per ECMAScript rules and never produces scientific notation for safe integers.
    return JSON.stringify(value);
  }

  // string — custom serializer to avoid \uXXXX escaping of non-ASCII characters
  if (typeof value === 'string') {
    return serializeString(value);
  }

  // array
  if (Array.isArray(value)) {
    if (_seen.has(value)) {
      throw new TypeError('canonicalJson: circular reference detected in array');
    }
    _seen.add(value);
    const elements = value.map((el) => {
      // JSON arrays represent undefined/function elements as null
      if (el === undefined || typeof el === 'function' || typeof el === 'symbol') {
        return 'null';
      }
      return canonicalJson(el, _seen);
    });
    _seen.delete(value);
    return '[' + elements.join(',') + ']';
  }

  // object
  if (typeof value === 'object') {
    if (_seen.has(value)) {
      throw new TypeError('canonicalJson: circular reference detected in object');
    }
    _seen.add(value);

    const sortedKeys = Object.keys(value).sort();
    const pairs = [];
    for (const key of sortedKeys) {
      const v = value[key];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
        // Skip undefined/non-serializable values per JSON semantics
        continue;
      }
      pairs.push(serializeString(key) + ':' + canonicalJson(v, _seen));
    }

    _seen.delete(value);
    return '{' + pairs.join(',') + '}';
  }

  // function, symbol, or other non-serializable
  if (typeof value === 'function' || typeof value === 'symbol') {
    throw new TypeError(
      `canonicalJson: ${typeof value} values cannot be serialized to JSON`
    );
  }

  // Fallback — should never reach here for well-typed JS values
  throw new TypeError(`canonicalJson: unrecognised value type: ${typeof value}`);
}

/**
 * Serialize a JavaScript string to a JSON string token, preserving non-ASCII
 * characters as literal UTF-8 rather than \uXXXX escape sequences.
 *
 * Only the characters mandated by the JSON specification are escaped:
 *   - " (quotation mark)         → \"
 *   - \ (reverse solidus)        → \\
 *   - Control characters U+0000–U+001F → \uXXXX (required by JSON spec)
 *
 * Non-ASCII characters (U+0080 and above) are preserved as-is, satisfying the
 * LOGN-HASH-v1 requirement that "Unicode characters in string values: preserved as-is in UTF-8".
 *
 * @param {string} str - The string to serialize.
 * @returns {string} JSON-encoded string token (with surrounding double quotes).
 */
function serializeString(str) {
  let result = '"';
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const code = str.charCodeAt(i);

    if (char === '"') {
      result += '\\"';
    } else if (char === '\\') {
      result += '\\\\';
    } else if (char === '\b') {
      result += '\\b';
    } else if (char === '\t') {
      result += '\\t';
    } else if (char === '\n') {
      result += '\\n';
    } else if (char === '\f') {
      result += '\\f';
    } else if (char === '\r') {
      result += '\\r';
    } else if (code < 0x20) {
      // Control characters (U+0000–U+001F) other than the 5 above must be \u00xx per RFC 8785 §3.2.2.2
      result += '\\u' + code.toString(16).padStart(4, '0');
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate: verify followed by valid low surrogate
      if (i + 1 < str.length) {
        const nextCode = str.charCodeAt(i + 1);
        if (nextCode >= 0xdc00 && nextCode <= 0xdfff) {
          result += char + str[i + 1];
          i++;
          continue;
        }
      }
      throw new TypeError(`canonicalJson: string contains unpaired surrogate at index ${i}`);
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      // Unpaired low surrogate
      throw new TypeError(`canonicalJson: string contains unpaired surrogate at index ${i}`);
    } else {
      // U+0020 and above (including all valid Unicode) — preserve as literal UTF-8 character
      result += char;
    }
  }
  result += '"';
  return result;
}

export default canonicalJson;
