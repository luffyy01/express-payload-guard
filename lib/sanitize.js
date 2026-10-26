const { DANGEROUS_KEYS, isPlainObject, isNoSqlKey, stripHtml } = require('./utils');

function cleanValue(val, opts, violations, depth = 0) {
  if (depth > (opts.maxDepth || 10)) {
    violations.push({ type: 'MAX_DEPTH_EXCEEDED', message: `Payload exceeded max nesting depth of ${opts.maxDepth || 10}` });
    return undefined;
  }

  if (typeof val === 'string') {
    let res = val;
    if (opts.trim !== false) {
      res = res.trim();
    }
    if (opts.xss) {
      const stripped = stripHtml(res);
      if (stripped !== res) {
        violations.push({ type: 'XSS_DETECTED', message: 'HTML tags removed from string input' });
      }
      res = stripped;
    }
    return res;
  }

  if (Array.isArray(val)) {
    const list = [];
    for (let i = 0; i < val.length; i++) {
      const item = cleanValue(val[i], opts, violations, depth + 1);
      if (item !== undefined) list.push(item);
    }
    return list;
  }

  if (isPlainObject(val)) {
    const clean = {};
    const whitelist = Array.isArray(opts.whitelist) ? opts.whitelist : [];

    for (const key of Object.keys(val)) {
      if (DANGEROUS_KEYS.has(key)) {
        violations.push({ type: 'PROTOTYPE_POLLUTION', key, message: `Dangerous prototype key '${key}' blocked` });
        continue;
      }

      if (opts.noSql !== false && isNoSqlKey(key) && !whitelist.includes(key)) {
        violations.push({ type: 'NOSQL_INJECTION', key, message: `NoSQL operator key '${key}' removed` });
        continue;
      }

      const cleanedVal = cleanValue(val[key], opts, violations, depth + 1);
      if (cleanedVal !== undefined) {
        clean[key] = cleanedVal;
      }
    }
    return clean;
  }

  return val;
}

function sanitize(input, options = {}) {
  const opts = {
    noSql: true,
    protoPollution: true,
    trim: true,
    xss: false,
    maxDepth: 10,
    whitelist: [],
    ...options
  };

  const violations = [];
  const data = cleanValue(input, opts, violations, 0);

  return {
    data,
    violations,
    isValid: violations.length === 0
  };
}

module.exports = {
  cleanValue,
  sanitize
};
